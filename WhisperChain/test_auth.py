########## imports ##########
import secrets
import time

from database.db import initialize_database, get_connection
from core.users import register_user, get_user, get_all_users
from core.auth import (
    hash_password,
    verify_password,
    set_password,
    authenticate,
    change_password,
    assign_default_password,
    GENERIC_LOGIN_ERROR,
    DEFAULT_PASSWORD
)


'''print PASS or FAIL for one check'''
def check(passed, description):
    print(("PASS: " if passed else "FAIL: ") + description)


'''return the error message from a call that should fail, or None'''
def error_from(action):
    try:
        action()
        return None
    except (PermissionError, ValueError) as error:
        return str(error)


# --------------------------------------------------
# DATABASE SETUP
# --------------------------------------------------

initialize_database()

suffix = secrets.token_hex(4)

admin_name = f"auth_admin_{suffix}"
alice_name = f"auth_alice_{suffix}"
bob_name = f"auth_bob_{suffix}"

with get_connection() as conn:
    admin_id = conn.execute(
        "INSERT INTO users (username, role) VALUES (?, ?)",
        (admin_name, "admin")
    ).lastrowid

set_password(admin_id, "admin-pass-1")

alice_id = register_user(admin_id, alice_name, "sender")
bob_id = register_user(admin_id, bob_name, "recipient")
mod_id = register_user(admin_id, f"auth_mod_{suffix}", "moderator")
nopass_id = register_user(admin_id, f"auth_nopass_{suffix}", "sender")   # never given a password

set_password(alice_id, "alice-pass-1")
set_password(bob_id, "alice-pass-1")         # same password on purpose (Test 1)
set_password(mod_id, "mod-pass-1")


# --------------------------------------------------
# TEST 1: PASSWORDS ARE HASHED AND SALTED
# --------------------------------------------------

print("\nTest 1: Password storage")

with get_connection() as conn:
    rows = {
        r["user_id"]: r["password_hash"]
        for r in conn.execute(
            "SELECT user_id, password_hash FROM users WHERE user_id IN (?, ?)",
            (alice_id, bob_id)
        )
    }

check("alice-pass-1" not in rows[alice_id], "Password is not stored in plaintext")
check(rows[alice_id].startswith("scrypt$"), "Password is hashed with scrypt")
check(rows[alice_id] != rows[bob_id], "Same password, different hashes (salted)")
check(verify_password("alice-pass-1", rows[alice_id]), "Correct password verifies")
check(not verify_password("alice-pass-2", rows[alice_id]), "Wrong password does not verify")


# --------------------------------------------------
# TEST 2: LOGGING IN
# --------------------------------------------------

print("\nTest 2: Login")

user = authenticate(alice_name, "alice-pass-1")

check(user["user_id"] == alice_id and user["role"] == "sender", "Correct password logs in")
check("password_hash" not in user, "Login result contains no password hash")

wrong_password = error_from(lambda: authenticate(alice_name, "nope-nope-1"))
unknown_user = error_from(lambda: authenticate(f"ghost_{suffix}", "nope-nope-1"))
no_password = error_from(lambda: authenticate(f"auth_nopass_{suffix}", "anything-1"))

check(wrong_password == GENERIC_LOGIN_ERROR, "Wrong password refused")
check(unknown_user == GENERIC_LOGIN_ERROR, "Unknown username gives the same error")
check(no_password == GENERIC_LOGIN_ERROR, "Account with no password can't log in")

# an unknown username should take about as long as a wrong password
start = time.perf_counter()
error_from(lambda: authenticate(alice_name, "nope-nope-1"))
known_time = time.perf_counter() - start

start = time.perf_counter()
error_from(lambda: authenticate(f"ghost_{suffix}", "nope-nope-1"))
unknown_time = time.perf_counter() - start

check(unknown_time > 0.3 * known_time,
      "Unknown username isn't noticeably faster (no timing leak)")



# --------------------------------------------------
# TEST 3: TEMPORARY PASSWORDS
# --------------------------------------------------

print("\nTest 3: Default password")

temporary = assign_default_password(admin_id, bob_id)
user = authenticate(bob_name, temporary)

check(temporary == DEFAULT_PASSWORD, "New account gets the default password")
check(user["must_change_password"] is True, "Default password must be changed")

change_password(bob_id, temporary, "bob-own-pass-1")
user = authenticate(bob_name, "bob-own-pass-1")

check(user["must_change_password"] is False, "Flag cleared after choosing a password")
check(error_from(lambda: authenticate(bob_name, temporary)) == GENERIC_LOGIN_ERROR,
      "Default password stops working once changed")


# --------------------------------------------------
# TEST 4: PASSWORD RULES
# --------------------------------------------------

print("\nTest 4: Password rules")

check(error_from(lambda: change_password(bob_id, "bob-own-pass-1", "")) is not None,
      "Empty password rejected")
check(error_from(lambda: change_password(bob_id, "bob-own-pass-1", "bob-own-pass-1")) is not None,
      "New password must differ from the current one")
check(error_from(lambda: change_password(bob_id, "not-my-pass-1", "bob-new-pass-2")) is not None,
      "Changing a password requires the current one")


# --------------------------------------------------
# TEST 5: NO LOCKOUT
# --------------------------------------------------

print("\nTest 5: Repeated failures don't lock the account")

for _ in range(10):
    error_from(lambda: authenticate(alice_name, "guess-guess-1"))

check(authenticate(alice_name, "alice-pass-1")["user_id"] == alice_id,
      "Correct password still works after 10 wrong guesses")

temporary = assign_default_password(admin_id, alice_id)

check(authenticate(alice_name, temporary)["user_id"] == alice_id,
      "Admin can reset a user to the default password")


# --------------------------------------------------
# TEST 6: ONLY ADMINS RESET PASSWORDS
# --------------------------------------------------

print("\nTest 6: Password reset permissions")

for uid, role in [(alice_id, "sender"), (bob_id, "recipient"), (mod_id, "moderator")]:
    try:
        assign_default_password(uid, admin_id)
        check(False, f"{role} reset a password")
    except PermissionError:
        check(True, f"{role} cannot reset passwords")


# --------------------------------------------------
# TEST 7: HASHES STAY HIDDEN
# --------------------------------------------------

print("\nTest 7: Password hashes stay hidden")

check("password_hash" not in get_user(alice_id), "get_user returns no password hash")
check(all("password_hash" not in u for u in get_all_users()),
      "get_all_users returns no password hashes")


# --------------------------------------------------
# TEST 8: AUDIT LOG
# --------------------------------------------------

print("\nTest 8: Login events in the audit log")

with get_connection() as conn:
    actions = {r["action"] for r in conn.execute("SELECT action FROM audit_log")}
    full_log = " ".join(str(tuple(r)) for r in conn.execute("SELECT * FROM audit_log"))

for expected in ["login_success", "login_failed",
                 "password_changed", "password_reset"]:
    check(expected in actions, f"{expected} logged")

secrets_in_log = ["alice-pass-1", "bob-own-pass-1", temporary, alice_name, bob_name]

check(not any(s in full_log for s in secrets_in_log),
      "No passwords or usernames in the audit log")