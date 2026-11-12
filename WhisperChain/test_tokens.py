from database.db import initialize_database, get_connection
from core.users import register_user
from core.tokens import (
    request_token, blind_token, issue_blind_signature, unblind_signature,
    redeem_token, verify_token, freeze_token, is_token_frozen,
    start_new_round, get_current_round, compute_token_id
)


# Initialize the database and create tables
initialize_database()


'''helper: return the user ID for a username, registering it if needed'''
def get_or_create(admin_id, username, role):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT user_id FROM users WHERE username = ?", (username,)
        ).fetchone()
    return row["user_id"] if row else register_user(admin_id, username, role)


# Find or create the initial administrator
with get_connection() as conn:
    admin = conn.execute(
        "SELECT user_id FROM users WHERE role = 'admin' LIMIT 1"
    ).fetchone()
    if admin is None:
        admin_id = conn.execute(
            "INSERT INTO users (username, role) VALUES (?, ?)",
            ("david", "admin")
        ).lastrowid
    else:
        admin_id = admin["user_id"]

sender_id = get_or_create(admin_id, "token_sender", "sender")
sender2_id = get_or_create(admin_id, "token_sender2", "sender")
recipient_id = get_or_create(admin_id, "token_recipient", "recipient")
moderator_id = get_or_create(admin_id, "token_moderator", "moderator")


# Start a fresh round so the tests can be re-run
round_id = start_new_round(admin_id)
print(f"Starting round {round_id}")


# Test 1: Sender obtains a valid token
print("\nTest 1: Sender requests a token")
token = request_token(sender_id)
print("PASS" if verify_token(token) else "FAIL", "- token signature valid")


# Test 2: Sender cannot get a second token in the same round
print("\nTest 2: Second token in same round")
try:
    request_token(sender_id)
    print("FAIL: Second token issued")
except PermissionError:
    print("PASS: One token per round enforced")


# Test 3: Non-senders cannot obtain tokens
print("\nTest 3: Non-sender requests a token")
for uid, role in [(recipient_id, "recipient"), (moderator_id, "moderator"),
                  (admin_id, "admin")]:
    try:
        request_token(uid)
        print(f"FAIL: {role} received a token")
    except PermissionError:
        print(f"PASS: {role} cannot obtain tokens")


# Test 4: Unlinkability. The server never sees what it signs
print("\nTest 4: Unlinkability")
blinded, state = blind_token(round_id)
blind_sig = issue_blind_signature(sender2_id, blinded)   # server's view
token2 = unblind_signature(blind_sig, state)             # client's result
server_saw = {blinded, blind_sig}
leaked = token2["signature"] in server_saw or token2["serial"] in str(server_saw)
print("FAIL: server saw the token" if leaked
      else "PASS: server never saw the final token or signature")

with get_connection() as conn:
    issuance_cols = [r[1] for r in conn.execute("PRAGMA table_info(token_issuance)")]
    token_cols = [r[1] for r in conn.execute("PRAGMA table_info(tokens)")]
print("token_issuance columns:", issuance_cols)
print("tokens columns:        ", token_cols)
print("PASS: no shared key links users to tokens"
      if "user_id" not in token_cols else "FAIL: tokens table stores user_id")


# Test 5: Redeeming a valid token
print("\nTest 5: Redeem valid token")
token_id = redeem_token(token)
print("PASS: token redeemed, id =", token_id[:16] + "...")


# Test 6: Double-spending is rejected
print("\nTest 6: Double-spend")
try:
    redeem_token(token)
    print("FAIL: Token used twice")
except PermissionError:
    print("PASS: Reused token rejected")


# Test 7: Forged tokens are rejected
print("\nTest 7: Forged token")
forged = {"round_id": round_id, "serial": "deadbeef" * 8, "signature": 12345}
tampered = dict(token2, serial="0" * 64)
for name, fake in [("random signature", forged), ("altered serial", tampered)]:
    try:
        redeem_token(fake)
        print(f"FAIL: {name} accepted")
    except PermissionError:
        print(f"PASS: {name} rejected")


# Test 8: Only moderators can freeze tokens
print("\nTest 8: Freeze permissions")
for uid, role in [(admin_id, "admin"), (sender_id, "sender")]:
    try:
        freeze_token(uid, token_id)
        print(f"FAIL: {role} froze a token")
    except PermissionError:
        print(f"PASS: {role} cannot freeze tokens")

freeze_token(moderator_id, token_id)
print("PASS: moderator froze token" if is_token_frozen(token_id)
      else "FAIL: token not frozen")


# Test 9: Tokens expire when a new round starts
print("\nTest 9: Expired round")
start_new_round(admin_id)
try:
    redeem_token(token2)
    print("FAIL: Old-round token accepted")
except PermissionError:
    print("PASS: Old-round token rejected")

new_token = request_token(sender_id)
print("PASS: sender gets a fresh token in the new round"
      if verify_token(new_token) else "FAIL")


# Test 10: Audit log records events without identities
print("\nTest 10: Audit log")
with get_connection() as conn:
    rows = conn.execute(
        "SELECT timestamp, action, role, details FROM audit_log "
        "ORDER BY log_id DESC LIMIT 8"
    ).fetchall()
    usernames = [r["username"] for r in conn.execute("SELECT username FROM users")]

for r in reversed(rows):
    print(" ", dict(r))

log_text = " ".join(str(dict(r)) for r in rows)
print("FAIL: usernames found in log" if any(u in log_text for u in usernames)
      else "PASS: no usernames in audit log")

try:
    with get_connection() as conn:
        conn.execute("DELETE FROM audit_log")
    print("FAIL: audit log was modified")
except Exception:
    print("PASS: audit log is append-only")