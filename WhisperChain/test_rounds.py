########## imports ##########
import secrets

from database.db import initialize_database, get_connection
from core.users import register_user
from core.rounds import (
    get_current_round,
    advance_round,
    is_active_round
)
from core.tokens import issue_token, validate_token


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

# Register Sender and Recipient
sender_id = register_user(
    admin_id, f"test_sender_{suffix}", "sender"
)

recipient_id = register_user(
    admin_id, f"test_recipient_{suffix}", "recipient"
)


# --------------------------------------------------
# TEST 1: CURRENT ROUND
# --------------------------------------------------

print("\nTest 1: Current round")

initial_round = get_current_round()

assert isinstance(initial_round, int)
assert initial_round > 0

print("PASS: Current round is", initial_round)


# --------------------------------------------------
# TEST 2: ACTIVE ROUND VALIDATION
# --------------------------------------------------

print("\nTest 2: Active round validation")

assert is_active_round(initial_round) is True
assert is_active_round(initial_round + 1) is False

print("PASS: Active round validation works")


# --------------------------------------------------
# TEST 3: TOKEN ISSUANCE
# --------------------------------------------------

print("\nTest 3: Token issuance")

token = issue_token(sender_id, initial_round)

assert validate_token(token, initial_round) is True

print("PASS: Token issued for active round")


# --------------------------------------------------
# TEST 4: ADVANCE ROUND
# --------------------------------------------------

print("\nTest 4: Advance round")

new_round = advance_round(admin_id)

assert new_round == initial_round + 1
assert get_current_round() == new_round

print("PASS: Advanced to round", new_round)


# --------------------------------------------------
# TEST 5: OLD TOKEN REJECTION
# --------------------------------------------------

print("\nTest 5: Old token rejection")

assert validate_token(token, initial_round) is False

print("PASS: Previous-round token rejected")


# --------------------------------------------------
# TEST 6: NEW ROUND TOKEN
# --------------------------------------------------

print("\nTest 6: New round token")

new_token = issue_token(sender_id, new_round)

assert validate_token(new_token, new_round) is True

print("PASS: New token issued for active round")


# --------------------------------------------------
# TEST 7: UNAUTHORIZED ROUND ADVANCEMENT
# --------------------------------------------------

print("\nTest 7: Unauthorized round advancement")

try:
    advance_round(sender_id)
    print("FAIL: Sender advanced the round")

except PermissionError:
    print("PASS: Sender cannot advance rounds")


# --------------------------------------------------
# TEST 8: INACTIVE ROUND ISSUANCE
# --------------------------------------------------

print("\nTest 8: Inactive round issuance")

try:
    issue_token(sender_id, initial_round)
    print("FAIL: Token issued for inactive round")

except ValueError:
    print("PASS: Cannot issue tokens for inactive rounds")

