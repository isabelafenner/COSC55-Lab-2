########## imports ##########
import secrets

from database.db import initialize_database, get_connection
from core.users import register_user
from core.rounds import get_current_round
from core.tokens import issue_token
from core.keys import setup_user_keys
from core.messages import send_message, get_messages
from core.client import read_message
from core.audit import get_audit_log, verify_audit_log


# --------------------------------------------------
# DATABASE SETUP
# --------------------------------------------------

initialize_database()

suffix = secrets.token_hex(4)

# Create test administrator
with get_connection() as conn:
    cursor = conn.execute(
        """
        INSERT INTO users (username, role)
        VALUES (?, ?)
        """,
        (f"test_admin_{suffix}", "admin")
    )

    admin_id = cursor.lastrowid

sender_id = register_user(admin_id, f"test_sender_{suffix}", "sender")
recipient_id = register_user(admin_id, f"test_recipient_{suffix}", "recipient")
moderator_id = register_user(admin_id, f"test_moderator_{suffix}", "moderator")

setup_user_keys(recipient_id)

# Perform a full message flow so there is something to log
secret_text = f"Audit test message {suffix}"

token = issue_token(sender_id, get_current_round())
message_id = send_message(token, recipient_id, secret_text)
get_messages(recipient_id)
read_message(recipient_id, message_id)


# --------------------------------------------------
# TEST 1: EVENTS ARE LOGGED
# --------------------------------------------------

print("\nTest 1: Events are logged")

entries = get_audit_log(moderator_id, limit=10)

for entry in reversed(entries):
    print(" ", entry)

actions = {entry["action"] for entry in entries}

for expected in ["user_registered", "token_issued", "message_sent",
                 "messages_delivered", "message_read"]:
    if expected in actions:
        print(f"PASS: {expected} logged")
    else:
        print(f"FAIL: {expected} missing from log")


# --------------------------------------------------
# TEST 2: NO IDENTITIES OR CONTENT IN THE LOG
# --------------------------------------------------

print("\nTest 2: No identities or content in the log")

with get_connection() as conn:
    usernames = [row["username"] for row in conn.execute("SELECT username FROM users")]
    full_log = " ".join(
        str(tuple(row)) for row in conn.execute("SELECT * FROM audit_log")
    )

if any(name in full_log for name in usernames):
    print("FAIL: Usernames found in audit log")
else:
    print("PASS: No usernames in audit log")

if token in full_log:
    print("FAIL: Full token found in audit log")
else:
    print("PASS: No full tokens in audit log")

if secret_text in full_log:
    print("FAIL: Message content found in audit log")
else:
    print("PASS: No message content in audit log")


# --------------------------------------------------
# TEST 3: ONLY MODERATORS CAN VIEW THE LOG
# --------------------------------------------------

print("\nTest 3: Audit log access")

for user_id, role in [(admin_id, "admin"),
                      (sender_id, "sender"),
                      (recipient_id, "recipient")]:
    try:
        get_audit_log(user_id)
        print(f"FAIL: {role} viewed the audit log")
    except PermissionError:
        print(f"PASS: {role} cannot view the audit log")


# --------------------------------------------------
# TEST 4: APPEND-ONLY
# --------------------------------------------------

print("\nTest 4: Append-only")

for name, statement in [("edit", "UPDATE audit_log SET action = 'hidden'"),
                        ("delete", "DELETE FROM audit_log")]:
    try:
        with get_connection() as conn:
            conn.execute(statement)
        print(f"FAIL: Audit log entries can be {name}ed")
    except Exception:
        print(f"PASS: Audit log entries cannot be {name}ed")


# --------------------------------------------------
# TEST 5: HASH CHAIN
# --------------------------------------------------

print("\nTest 5: Hash chain")

result = verify_audit_log(moderator_id)
print("Verification:", result)

if result["valid"]:
    print("PASS: Every audit log entry links to the one before it")
else:
    print("FAIL: Audit log chain is broken")

try:
    verify_audit_log(admin_id)
    print("FAIL: Admin ran log verification")
except PermissionError:
    print("PASS: Only moderators can verify the log")