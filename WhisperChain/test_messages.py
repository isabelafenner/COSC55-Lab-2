########## imports ##########
import json
import secrets

from database.db import initialize_database, get_connection
from core.users import register_user, get_user
from core.rounds import get_current_round, advance_round
from core.tokens import issue_token, freeze_token
from core.keys import (
    setup_user_keys,
    register_public_key,
    reset_public_key,
    load_user_private_key,
    _private_key_path
)
from core.crypto import generate_key_pair, decrypt_message
from core.messages import send_message, get_messages, get_message
from core.client import read_message, read_inbox


# --------------------------------------------------
# DATABASE SETUP
# --------------------------------------------------

# Create database tables if they do not already exist
initialize_database()

# Generate unique usernames so tests can be rerun
suffix = secrets.token_hex(4)

# Create an initial administrator
with get_connection() as conn:
    cursor = conn.execute(
        """
        INSERT INTO users (username, role)
        VALUES (?, ?)
        """,
        (f"test_admin_{suffix}", "admin")
    )

    admin_id = cursor.lastrowid

# Register the remaining users through the Admin
sender_id = register_user(admin_id, f"test_sender_{suffix}", "sender")
sender2_id = register_user(admin_id, f"test_sender2_{suffix}", "sender")
sender3_id = register_user(admin_id, f"test_sender3_{suffix}", "sender")
recipient_id = register_user(admin_id, f"test_recipient_{suffix}", "recipient")
recipient2_id = register_user(admin_id, f"test_recipient2_{suffix}", "recipient")
moderator_id = register_user(admin_id, f"test_moderator_{suffix}", "moderator")

# Each user generates a key pair: public key -> server, private key -> device
for user_id in [sender_id, sender2_id, sender3_id,
                recipient_id, recipient2_id, moderator_id]:
    setup_user_keys(user_id)

round_id = get_current_round()


# --------------------------------------------------
# TEST 1: KEY STORAGE
# --------------------------------------------------

print("\nTest 1: Key storage")

assert "BEGIN PUBLIC KEY" in get_user(recipient_id)["public_key"]
assert _private_key_path(recipient_id).exists()

with get_connection() as conn:
    stored = " ".join(
        str(value)
        for row in conn.execute("SELECT * FROM users")
        for value in tuple(row)
    )

assert "PRIVATE KEY" not in stored

print("PASS: Public key on server, private key only on the user's device")


# --------------------------------------------------
# TEST 2: KEY REPLACEMENT PROTECTION
# --------------------------------------------------

print("\nTest 2: Key replacement protection")

attacker_public_key, _ = generate_key_pair()

try:
    register_public_key(recipient2_id, attacker_public_key)
    print("FAIL: Registered key was overwritten")
except PermissionError:
    print("PASS: Registered key cannot be overwritten")

try:
    reset_public_key(sender_id, recipient2_id)
    print("FAIL: Sender reset a key")
except PermissionError:
    print("PASS: Non-admin cannot reset keys")

assert reset_public_key(admin_id, recipient2_id) is True
setup_user_keys(recipient2_id)

print("PASS: Admin reset key, user registered a new one")


# --------------------------------------------------
# TEST 3: SEND AND READ AN ENCRYPTED MESSAGE
# --------------------------------------------------

print("\nTest 3: Encrypted send and receive")

secret_text = f"Thanks for staying late to help me debug! ({suffix})"

token = issue_token(sender_id, round_id)
message_id = send_message(token, recipient_id, secret_text)

# client side: fetch ciphertext from the server, decrypt on the device
decrypted = read_message(recipient_id, message_id)

print("Recipient decrypted:", decrypted)
assert decrypted == secret_text

print("PASS: Recipient decrypted the message")

# the full inbox decrypts locally too
inbox_texts = [m["text"] for m in read_inbox(recipient_id)]
assert secret_text in inbox_texts

print("PASS: Recipient decrypted their inbox")


# --------------------------------------------------
# TEST 3b: SERVER NEVER DECRYPTS
# --------------------------------------------------

print("\nTest 3b: Server returns ciphertext only")

server_response = get_message(recipient_id, message_id)

assert secret_text not in server_response
assert all(secret_text not in m["ciphertext"] for m in get_messages(recipient_id))

print("PASS: Server responses contain only ciphertext")


# --------------------------------------------------
# TEST 4: WHAT THE SERVER STORES
# --------------------------------------------------

print("\nTest 4: What the server stores")

with get_connection() as conn:
    row = conn.execute(
        "SELECT * FROM messages WHERE message_id = ?",
        (message_id,)
    ).fetchone()

print("messages columns:", row.keys())
print("Stored ciphertext (first 60 chars):", row["ciphertext"][:60] + "...")

assert secret_text not in row["ciphertext"]
assert not any("sender" in column for column in row.keys())

print("PASS: Only ciphertext stored, no sender identity")


# --------------------------------------------------
# TEST 5: TOKEN REUSE
# --------------------------------------------------

print("\nTest 5: Token reuse")

try:
    send_message(token, recipient_id, "second message, same token")
    print("FAIL: Token was reused")
except ValueError:
    print("PASS: One message per token")


# --------------------------------------------------
# TEST 6: INVALID RECIPIENT
# --------------------------------------------------

print("\nTest 6: Invalid recipient")

token2 = issue_token(sender2_id, round_id)

try:
    send_message(token2, moderator_id, "hello moderator")
    print("FAIL: Message sent to a moderator")
except ValueError:
    print("PASS: Cannot send to non-recipients")

# the rejected send should not have used up the token
message2_id = send_message(token2, recipient2_id, "You ask great questions in class.")

print("PASS: Token still usable after the rejected send")


# --------------------------------------------------
# TEST 7: INBOX ISOLATION
# --------------------------------------------------

print("\nTest 7: Inbox isolation")

other_inbox = [m["message_id"] for m in get_messages(recipient2_id)]
assert message_id not in other_inbox

print("PASS: Inbox only returns your own messages")

try:
    read_message(recipient2_id, message_id)
    print("FAIL: Recipient read someone else's message")
except ValueError:
    print("PASS: Cannot open another recipient's message")

# even with raw database access, the wrong private key cannot decrypt
try:
    decrypt_message(row["ciphertext"], load_user_private_key(recipient2_id))
    print("FAIL: Wrong private key decrypted the message")
except ValueError:
    print("PASS: Wrong private key cannot decrypt")


# --------------------------------------------------
# TEST 8: INBOX ACCESS BY ROLE
# --------------------------------------------------

print("\nTest 8: Inbox access by role")

for user_id, role in [(admin_id, "admin"),
                      (moderator_id, "moderator"),
                      (sender_id, "sender")]:
    try:
        get_messages(user_id)
        print(f"FAIL: {role} accessed an inbox")
    except PermissionError:
        print(f"PASS: {role} cannot read messages")


# --------------------------------------------------
# TEST 9: TAMPER DETECTION
# --------------------------------------------------

print("\nTest 9: Tamper detection")

package = json.loads(row["ciphertext"])
body = package["encrypted_message"]

# change one character in the encrypted message body
middle = len(body) // 2
package["encrypted_message"] = (
    body[:middle] + ("A" if body[middle] != "A" else "B") + body[middle + 1:]
)

try:
    decrypt_message(json.dumps(package), load_user_private_key(recipient_id))
    print("FAIL: Tampered message was accepted")
except Exception:
    print("PASS: Tampered message rejected")


# --------------------------------------------------
# TEST 10: FROZEN TOKEN
# --------------------------------------------------

print("\nTest 10: Frozen token")

token3 = issue_token(sender3_id, round_id)
assert freeze_token(moderator_id, token3) is True

try:
    send_message(token3, recipient_id, "message from a frozen token")
    print("FAIL: Frozen token sent a message")
except ValueError:
    print("PASS: Frozen token cannot send")


# --------------------------------------------------
# TEST 11: EXPIRED ROUND
# --------------------------------------------------

print("\nTest 11: Expired round")

# issue a token, then move to the next round before using it
late_sender_id = register_user(admin_id, f"test_late_sender_{suffix}", "sender")
old_token = issue_token(late_sender_id, round_id)

advance_round(admin_id)

try:
    send_message(old_token, recipient_id, "sent after the round ended")
    print("FAIL: Old-round token sent a message")
except ValueError:
    print("PASS: Tokens expire when the round ends")