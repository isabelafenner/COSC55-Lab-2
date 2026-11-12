from database.db import initialize_database, get_connection
from core.users import register_user, get_user
from core.tokens import request_token, start_new_round, compute_token_id
from core.keys import (
    setup_user_keys, register_public_key, reset_public_key,
    load_user_private_key, _private_key_path
)
from core.crypto import generate_keypair, decrypt_message
from core.messages import (
    send_message, get_inbox, read_inbox, _associated_data
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


'''helper: make sure a user has a registered key AND a local private key'''
def ensure_keys(admin_id, user_id):
    has_server_key = get_user(user_id)["public_key"] is not None
    has_local_key = _private_key_path(user_id).exists()

    if has_server_key and has_local_key:
        return
    if has_server_key:
        reset_public_key(admin_id, user_id)   # key on server but lost locally
    setup_user_keys(user_id)


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

sender_id = get_or_create(admin_id, "msg_sender", "sender")
sender2_id = get_or_create(admin_id, "msg_sender2", "sender")
recipient_id = get_or_create(admin_id, "msg_recipient", "recipient")
recipient2_id = get_or_create(admin_id, "msg_recipient2", "recipient")
moderator_id = get_or_create(admin_id, "msg_moderator", "moderator")
keytest_id = get_or_create(admin_id, "msg_keytest", "recipient")

for uid in [sender_id, sender2_id, recipient_id, recipient2_id, moderator_id, keytest_id]:
    ensure_keys(admin_id, uid)

# Fresh round so each sender can get a token every run
round_id = start_new_round(admin_id)
print(f"Starting round {round_id}")


# Test 1: Key setup keeps private keys off the server
print("\nTest 1: Key storage")
with get_connection() as conn:
    stored = " ".join(
        str(v) for row in conn.execute("SELECT * FROM users") for v in tuple(row)
    )
print("PASS: public key stored on server"
      if "BEGIN PUBLIC KEY" in get_user(recipient_id)["public_key"] else "FAIL")
print("FAIL: private key found in database" if "PRIVATE KEY" in stored
      else "PASS: no private keys in database")


# Test 2: Public keys can't be silently replaced
print("\nTest 2: Key replacement")
_, attacker_pub = generate_keypair()
try:
    register_public_key(keytest_id, attacker_pub)
    print("FAIL: existing key overwritten")
except PermissionError:
    print("PASS: registered key cannot be overwritten")

try:
    reset_public_key(sender_id, keytest_id)
    print("FAIL: sender reset a key")
except PermissionError:
    print("PASS: non-admin cannot reset keys")

reset_public_key(admin_id, keytest_id)
setup_user_keys(keytest_id)
print("PASS: admin reset key, user registered a new one")


# Test 3: Send and read an encrypted message
print("\nTest 3: Encrypted send and receive")
secret_text = f"Thanks for staying late to help me debug (round {round_id})!"
token = request_token(sender_id)
message_id = send_message(token, recipient_id, secret_text)

inbox = read_inbox(recipient_id)
received = next(m for m in inbox if m["message_id"] == message_id)
print("Recipient decrypted:", received["text"])
print("PASS: message decrypted correctly" if received["text"] == secret_text
      else "FAIL: wrong plaintext")


# Test 4: Server stores only ciphertext, with no sender info
print("\nTest 4: What the server stores")
with get_connection() as conn:
    row = conn.execute(
        "SELECT * FROM messages WHERE message_id = ?", (message_id,)
    ).fetchone()
    columns = row.keys()

print("messages columns:", columns)
print("Stored ciphertext (first 32 bytes):", row["ciphertext"][:32].hex())
print("FAIL: plaintext visible in database" if secret_text.encode() in row["ciphertext"]
      else "PASS: plaintext not stored")
print("FAIL: sender stored with message" if any("sender" in c for c in columns)
      else "PASS: no sender identity stored")


# Test 5: A token can only send one message
print("\nTest 5: Token reuse")
try:
    send_message(token, recipient_id, "second message, same token")
    print("FAIL: token reused")
except PermissionError:
    print("PASS: one message per token")


# Test 6: Only recipients can receive, and a failed send doesn't waste the token
print("\nTest 6: Invalid recipient")
token2 = request_token(sender2_id)
try:
    send_message(token2, moderator_id, "hello moderator")
    print("FAIL: message sent to a moderator")
except ValueError:
    print("PASS: cannot send to non-recipients")

message2_id = send_message(token2, recipient2_id, "You ask great questions in class.")
print("PASS: token still usable after the rejected send")


# Test 7: Recipients can only read their own messages
print("\nTest 7: Inbox isolation")
other_inbox_ids = [m["message_id"] for m in get_inbox(recipient2_id)]
print("FAIL: recipient2 can see recipient's message" if message_id in other_inbox_ids
      else "PASS: inbox only returns your own messages")

# even with raw database access, the wrong key can't decrypt
try:
    decrypt_message(
        load_user_private_key(recipient2_id),
        row["ciphertext"],
        _associated_data(recipient_id, row["token_id"])
    )
    print("FAIL: wrong key decrypted the message")
except ValueError:
    print("PASS: wrong private key cannot decrypt")


# Test 8: Other roles cannot read inboxes (separation of duties)
print("\nTest 8: Inbox access by role")
for uid, role in [(admin_id, "admin"), (moderator_id, "moderator"), (sender_id, "sender")]:
    try:
        get_inbox(uid)
        print(f"FAIL: {role} accessed an inbox")
    except PermissionError:
        print(f"PASS: {role} cannot read messages")


# Test 9: Tampering is detected
print("\nTest 9: Tamper detection")
recipient_key = load_user_private_key(recipient_id)
correct_ad = _associated_data(recipient_id, row["token_id"])

flipped = bytearray(row["ciphertext"])
flipped[-1] ^= 0x01
moved_ad = _associated_data(recipient2_id, row["token_id"])
swapped_ad = _associated_data(recipient_id, "0" * 64)

for name, ct, ad in [("altered ciphertext", bytes(flipped), correct_ad),
                     ("moved to another inbox", row["ciphertext"], moved_ad),
                     ("token_id swapped", row["ciphertext"], swapped_ad)]:
    try:
        decrypt_message(recipient_key, ct, ad)
        print(f"FAIL: {name} not detected")
    except ValueError:
        print(f"PASS: {name} detected")


# Test 10: Audit log records message events without identities or content
print("\nTest 10: Audit log")
with get_connection() as conn:
    rows = conn.execute(
        "SELECT timestamp, action, role, details FROM audit_log "
        "ORDER BY log_id DESC LIMIT 8"
    ).fetchall()
    usernames = [r["username"] for r in conn.execute("SELECT username FROM users")]
    all_log = " ".join(
        str(tuple(r)) for r in conn.execute("SELECT * FROM audit_log")
    )

for r in reversed(rows):
    print(" ", dict(r))

print("FAIL: usernames in audit log" if any(u in all_log for u in usernames)
      else "PASS: no usernames in audit log")
print("FAIL: message content in audit log" if secret_text in all_log
      else "PASS: no message content in audit log")