'''
WhisperChain+ command-line interface

Log in as any registered user and get a menu for that user's role.
The menu only offers actions the role is allowed to perform, and every
action is still checked by RBAC on the server side.

Usage:
    python main.py

Prototype note: login is by username only (no password). Authentication
is out of scope for this project; see THREAT_MODEL.md.
'''

########## imports ##########
import sys

from database.db import initialize_database, get_connection
from core.users import register_user, get_user, get_all_users, update_user_role
from core.rounds import get_current_round, advance_round
from core.tokens import issue_token, freeze_token
from core.keys import setup_user_keys, reset_public_key, _private_key_path
from core.messages import send_message
from core.client import read_inbox, flag_message, save_token, load_token, clear_token
from core.moderation import get_flag_queue, review_flag, get_alerts
from core.audit import log_event, get_audit_log, verify_audit_log


ROLES = ("sender", "recipient", "moderator", "admin")


# =====================================================================
# Input and lookup helpers
# =====================================================================

'''read a line of input; exit cleanly if input ends'''
def ask(prompt):
    try:
        return input(prompt).strip()
    except EOFError:
        print("\nGoodbye.")
        sys.exit(0)


'''read a whole number, or raise ValueError'''
def ask_int(prompt):
    value = ask(prompt)

    if not value.isdigit():
        raise ValueError("Please enter a number.")

    return int(value)


'''find a user by username, or None'''
def find_user(username):
    for user in get_all_users():
        if user["username"] == username:
            return user
    return None


'''find a user by username, or raise ValueError'''
def require_user(username):
    user = find_user(username)

    if user is None:
        raise ValueError(f"No user named '{username}'.")

    return user


# =====================================================================
# Setup
# =====================================================================

'''
Function: bootstrap_admin
Description: On a brand-new system, creates the first administrator.
             This is the only account created without an existing admin.
'''
def bootstrap_admin():

    with get_connection() as conn:
        admin = conn.execute(
            "SELECT 1 FROM users WHERE role = 'admin' LIMIT 1"
        ).fetchone()

    if admin:
        return

    print("\nNo administrator exists yet. Create the first admin account.")

    while True:
        username = ask("Admin username: ")

        if username:
            break

        print("  Username cannot be empty.")

    with get_connection() as conn:
        conn.execute(
            "INSERT INTO users (username, role) VALUES (?, ?)",
            (username, "admin")
        )
        log_event(conn, "user_registered", "admin", "role=admin bootstrap")

    print(f"  Admin '{username}' created. Log in with that username.")


'''
Function: ensure_keys
Description: On first login, generates the user's key pair. Warns if the
             server has a key but this device has lost the private half.
'''
def ensure_keys(user):

    if user["public_key"] is None:
        setup_user_keys(user["user_id"])
        print("  Generated your key pair. Private key saved on this device only.")

    elif not _private_key_path(user["user_id"]).exists():
        print("  ! Your private key is missing from this device.")
        print("    You won't be able to read messages. Ask an admin to reset your key,")
        print("    then log in again to generate a new one.")


# =====================================================================
# Sender actions
# =====================================================================

'''get this round's token: the saved one if unused, otherwise a new one'''
def current_token(user):

    round_id = get_current_round()
    saved = load_token(user["user_id"])

    if saved and saved["round_id"] == round_id:
        return saved["token"]

    token = issue_token(user["user_id"], round_id)
    save_token(user["user_id"], round_id, token)

    return token


def sender_token_status(user):

    round_id = get_current_round()
    saved = load_token(user["user_id"])

    if saved and saved["round_id"] == round_id:
        print(f"  You have an unused token for round {round_id}.")
        return

    try:
        current_token(user)
        print(f"  New anonymous token issued for round {round_id}. Saved on this device.")
    except ValueError:
        print(f"  You've already used your token for round {round_id}.")
        print("  You can send again when the next round starts.")


def sender_send(user):

    # check for a usable token before asking for the message
    try:
        token = current_token(user)
    except ValueError:
        raise ValueError(
            f"You've already used your token for round {get_current_round()}. "
            "You can send again when the next round starts."
        )

    recipient = require_user(ask("Recipient username: "))
    text = ask("Message: ")

    send_message(token, recipient["user_id"], text)
    clear_token(user["user_id"])

    print("  Sent anonymously. Your token for this round is now used.")


# =====================================================================
# Recipient actions
# =====================================================================

def recipient_inbox(user):

    messages = read_inbox(user["user_id"])

    if not messages:
        print("  (no messages)")
        return

    for message in messages:
        print(f"  [{message['message_id']}] {message['text']}")


def recipient_flag(user):

    message_id = ask_int("Message number to flag: ")
    reason = ask("Reason (optional): ") or None

    flag_id = flag_message(user["user_id"], message_id, reason)

    print(f"  Flag {flag_id} submitted. Only this message was revealed to moderators.")


# =====================================================================
# Moderator actions
# =====================================================================

def moderator_queue(user):

    queue = get_flag_queue(user["user_id"])

    if not queue:
        print("  (no pending flags)")
        return

    for flag in queue:
        print(f"  Flag {flag['flag_id']}  round {flag['round_id']}  "
              f"token {flag['token_id'][:12]}...")
        print(f"    message: \"{flag['content']}\"")
        print(f"    reason:  {flag['reason'] or '(none)'}")


def moderator_review(user):

    flag_id = ask_int("Flag number: ")

    pending = {f["flag_id"]: f for f in get_flag_queue(user["user_id"])}

    if flag_id not in pending:
        raise ValueError("No pending flag with that number.")

    choice = ask("Uphold or dismiss? (u/d): ").lower()

    if choice not in ("u", "d"):
        raise ValueError("Please enter 'u' or 'd'.")

    decision = "upheld" if choice == "u" else "dismissed"
    review_flag(user["user_id"], flag_id, decision)

    print(f"  Flag {flag_id} {decision}.")

    if decision == "upheld" and ask("Freeze the token that sent it? (y/n): ").lower() == "y":
        freeze_token(user["user_id"], pending[flag_id]["token_id"])
        print("  Token frozen.")


def moderator_alerts(user):

    alerts = get_alerts(user["user_id"])

    if not alerts:
        print("  (no alerts)")
        return

    for alert in alerts:
        print(f"  {alert['created_at']}  round {alert['round_id']}  "
              f"{alert['rule']}  ({alert['details']})")


def moderator_audit_log(user):

    for entry in reversed(get_audit_log(user["user_id"], limit=20)):
        print(f"  {entry['timestamp']}  {entry['role']:<10} "
              f"{entry['action']:<22} {entry['details'] or ''}")


def moderator_verify(user):

    result = verify_audit_log(user["user_id"])

    if result["valid"]:
        print(f"  Audit log VALID ({result['entries_checked']} entries checked).")
    else:
        print(f"  ! Audit log BROKEN at entry {result['first_invalid_log_id']}.")


# =====================================================================
# Admin actions
# =====================================================================

def admin_list_users(user):

    print(f"  {'ID':<5}{'Username':<24}{'Role':<12}Key")

    for u in get_all_users():
        key = "yes" if u["public_key"] else "no"
        print(f"  {u['user_id']:<5}{u['username']:<24}{u['role']:<12}{key}")


def admin_register(user):

    username = ask("New username: ")
    role = ask(f"Role {ROLES}: ").lower()

    if role not in ROLES:
        raise ValueError(f"Role must be one of {', '.join(ROLES)}.")

    if find_user(username):
        raise ValueError(f"Username '{username}' is taken.")

    register_user(user["user_id"], username, role)

    print(f"  Registered '{username}' as {role}.")


def admin_change_role(user):

    target = require_user(ask("Username: "))
    role = ask(f"New role {ROLES}: ").lower()

    if role not in ROLES:
        raise ValueError(f"Role must be one of {', '.join(ROLES)}.")

    update_user_role(user["user_id"], target["user_id"], role)

    print(f"  '{target['username']}' is now {role}.")


def admin_reset_key(user):

    target = require_user(ask("Username: "))

    if reset_public_key(user["user_id"], target["user_id"]):
        print(f"  Key cleared. '{target['username']}' gets a new key pair at next login.")
    else:
        print(f"  '{target['username']}' had no key registered.")


def admin_advance_round(user):

    if ask("Start a new round? Unused tokens will expire. (y/n): ").lower() != "y":
        print("  Cancelled.")
        return

    print(f"  Round {advance_round(user['user_id'])} is now active.")


# =====================================================================
# Menus
# =====================================================================

# each role's menu: (label, action)
MENUS = {
    "sender": [
        ("Get / check my token for this round", sender_token_status),
        ("Send an anonymous message", sender_send),
    ],
    "recipient": [
        ("Read my inbox", recipient_inbox),
        ("Flag a message", recipient_flag),
    ],
    "moderator": [
        ("View pending flags", moderator_queue),
        ("Review a flag", moderator_review),
        ("View alerts", moderator_alerts),
        ("View audit log", moderator_audit_log),
        ("Verify audit log integrity", moderator_verify),
    ],
    "admin": [
        ("List users", admin_list_users),
        ("Register a user", admin_register),
        ("Change a user's role", admin_change_role),
        ("Reset a user's public key", admin_reset_key),
        ("Start a new round", admin_advance_round),
    ],
}


'''
Function: session
Description: Shows the logged-in user's role menu until they log out.
'''
def session(user_id):

    while True:

        # reload each time, in case an admin changed this user's role
        user = get_user(user_id)
        menu = MENUS[user["role"]]

        print(f"\n[{user['username']} | {user['role']} | round {get_current_round()}]")

        for number, (label, _) in enumerate(menu, start=1):
            print(f"  {number}. {label}")
        print("  0. Log out")

        choice = ask("> ")

        if choice == "0":
            print(f"  Logged out {user['username']}.")
            return

        if not choice.isdigit() or not 1 <= int(choice) <= len(menu):
            print("  Invalid choice.")
            continue

        _, action = menu[int(choice) - 1]

        try:
            action(user)
        except (PermissionError, ValueError, FileNotFoundError) as error:
            print(f"  ! {error}")


def main():

    initialize_database()

    print("=" * 50)
    print("WhisperChain+")
    print("=" * 50)

    bootstrap_admin()

    while True:

        username = ask("\nUsername (q to quit): ")

        if username.lower() in ("q", "quit"):
            print("Goodbye.")
            return

        user = find_user(username)

        if user is None:
            print("  No such user.")
            continue

        print(f"  Welcome, {user['username']}.")
        ensure_keys(user)
        session(user["user_id"])


if __name__ == "__main__":
    main()