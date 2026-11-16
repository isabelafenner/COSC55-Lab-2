########## imports ##########
import secrets
import sqlite3

from database.db import initialize_database, get_connection
from core.users import register_user, get_user
from core.tokens import (
    issue_token,
    validate_token,
    use_token,
    freeze_token
)
from core.rounds import get_current_round, advance_round


# --------------------------------------------------
# DATABASE SETUP
# --------------------------------------------------

# Create database tables if they do not already exist
initialize_database()

# Generate unique usernames so tests can be rerun
suffix = secrets.token_hex(4)

admin_username = f"test_admin_{suffix}"
sender_username = f"test_sender_{suffix}"
moderator_username = f"test_moderator_{suffix}"
recipient_username = f"test_recipient_{suffix}"


# Create an initial administrator
with get_connection() as conn:
    cursor = conn.execute(
        """
        INSERT INTO users (username, role)
        VALUES (?, ?)
        """,
        (admin_username, "admin")
    )

    admin_id = cursor.lastrowid


# Register the remaining users through the Admin
sender_id = register_user(
    admin_id, sender_username, "sender"
)

moderator_id = register_user(
    admin_id, moderator_username, "moderator"
)

recipient_id = register_user(
    admin_id, recipient_username, "recipient"
)


# --------------------------------------------------
# TEST 1: TOKEN ISSUANCE
# --------------------------------------------------

print("\nTest 1: Token issuance")

# use whatever round is currently active
round_id = get_current_round()

token = issue_token(sender_id, round_id)

print("Generated token:", token)

assert isinstance(token, str)
assert len(token) > 0

print("PASS: Sender received a token")


# --------------------------------------------------
# TEST 2: DUPLICATE TOKEN PREVENTION
# --------------------------------------------------

print("\nTest 2: Duplicate token prevention")

try:
    issue_token(sender_id, round_id)
    print("FAIL: Sender received a second token")

except ValueError:
    print("PASS: Sender cannot receive two tokens in one round")


# --------------------------------------------------
# TEST 3: INVALID ROLE
# --------------------------------------------------

print("\nTest 3: Invalid role")

try:
    issue_token(recipient_id, round_id)
    print("FAIL: Recipient received a token")

except PermissionError:
    print("PASS: Recipient cannot receive Sender tokens")


# --------------------------------------------------
# TEST 4: TOKEN VALIDATION
# --------------------------------------------------

print("\nTest 4: Token validation")

assert validate_token(token, round_id) is True
assert validate_token(token, round_id + 1) is False
assert validate_token("invalid_token", round_id) is False

print("PASS: Valid and invalid tokens handled correctly")


# --------------------------------------------------
# TEST 5: SINGLE-USE ENFORCEMENT
# --------------------------------------------------

print("\nTest 5: Single-use enforcement")

assert use_token(token, round_id) is True

# Token should now be invalid
assert validate_token(token, round_id) is False

# Attempting to reuse the token should fail
assert use_token(token, round_id) is False

print("PASS: Token can only be used once")


# --------------------------------------------------
# TEST 6: NEW ROUND
# --------------------------------------------------

print("\nTest 6: New round")

# the Admin advances to the next round
new_round = advance_round(admin_id)

new_token = issue_token(sender_id, new_round)

assert new_token != token
assert validate_token(new_token, new_round) is True

print("PASS: Sender can receive a new token in another round")


# --------------------------------------------------
# TEST 7: MODERATOR FREEZING
# --------------------------------------------------

print("\nTest 7: Moderator freezing")

assert freeze_token(moderator_id, new_token) is True

assert validate_token(new_token, new_round) is False
assert use_token(new_token, new_round) is False

print("PASS: Frozen tokens cannot be used")


# --------------------------------------------------
# TEST 8: UNAUTHORIZED FREEZING
# --------------------------------------------------

print("\nTest 8: Unauthorized freezing")

try:
    freeze_token(sender_id, token)
    print("FAIL: Sender froze a token")

except PermissionError:
    print("PASS: Sender cannot freeze tokens")


# --------------------------------------------------
# TEST 9: DATABASE SEPARATION
# --------------------------------------------------

print("\nTest 9: Token anonymity")

with get_connection() as conn:

    token_record = conn.execute(
        """
        SELECT *
        FROM tokens
        WHERE token_id = ?
        """,
        (token,)
    ).fetchone()

    assert token_record is not None

    # Token records must not contain user identities
    assert "user_id" not in token_record.keys()
    assert "username" not in token_record.keys()

print("PASS: Token records do not store user identities")

# tokens must not keep insertion order, or row N of tokens
# could be matched to row N of token_issuance
with get_connection() as conn:
    try:
        conn.execute("SELECT rowid FROM tokens LIMIT 1")
        print("FAIL: tokens table keeps insertion order (rowid)")
    except sqlite3.OperationalError:
        print("PASS: tokens stored without insertion order")