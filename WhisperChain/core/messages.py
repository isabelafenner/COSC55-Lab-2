########## imports ##########
from database.db import get_connection
from core.rbac import require_permission, has_permission
from core.users import get_user
from core.audit import log_event
from core.tokens import redeem_token, compute_token_id
from core.crypto import encrypt_message, decrypt_message
from core.keys import get_public_key, load_user_private_key


'''
OVERVIEW: Anonymous encrypted message flow

    SENDER DEVICE                      SERVER                     RECIPIENT DEVICE
    -------------                      ------                     ----------------
    fetch recipient public key  <----  users.public_key
    encrypt with it
    send (token, recipient, ct) ---->  verify + spend token
                                       store ciphertext only
                                       (no sender, no plaintext)
                                       get_inbox  ----------->    decrypt with own
                                                                  private key

    The server stores which inbox a message belongs to (it has to, to
    deliver it) and which anonymous token paid for it. It never learns who
    sent it or what it says.
'''


MAX_MESSAGE_CHARS = 1000
MAX_CIPHERTEXT_BYTES = 8192


'''
Function: _associated_data
Description: Context bound into the encryption. If the server moves a
             message to another inbox or swaps its token_id, decryption
             fails, so tampering is detected by the recipient.
'''
def _associated_data(recipient_id, token_id):
    return f"whisperchain-msg|{recipient_id}|{token_id}".encode()


'''
Function: _get_valid_recipient
Description: Checks that a user exists, has the recipient role, and has
             registered a public key.
Inputs:
    recipient_id (int): ID of the intended recipient.
Returns:
    str: Recipient's PEM public key.
Raises:
    ValueError: If the user cannot receive messages.
'''
def _get_valid_recipient(recipient_id):

    recipient = get_user(recipient_id)

    if recipient is None or not has_permission(recipient["role"], "read_messages"):
        raise ValueError("Invalid recipient.")

    if recipient["public_key"] is None:
        raise ValueError("Recipient has not registered a public key.")

    return recipient["public_key"]


# =====================================================================
# Server side
# =====================================================================

'''
Function: submit_message
Description: SERVER SIDE. Accepts an already-encrypted message. Takes NO
             sender ID: the token is the authorization, and it is spent here.
Inputs:
    token (dict): Anonymous token {round_id, serial, signature}.
    recipient_id (int): ID of the recipient.
    ciphertext (bytes): Encrypted message from encrypt_message.
Returns:
    int: ID of the stored message.
Raises:
    PermissionError: Invalid, expired, or already-used token.
    ValueError: Invalid recipient or malformed ciphertext.
'''
def submit_message(token, recipient_id, ciphertext):

    # validate everything BEFORE spending the token
    _get_valid_recipient(recipient_id)

    if not isinstance(ciphertext, bytes) or not (0 < len(ciphertext) <= MAX_CIPHERTEXT_BYTES):
        raise ValueError("Malformed ciphertext.")

    # spend the token (verifies signature, round, and single use)
    token_id = redeem_token(token)

    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO messages (recipient_id, round_id, token_id, ciphertext)
            VALUES (?, ?, ?, ?)
            """,
            (recipient_id, token["round_id"], token_id, ciphertext)
        )

        log_event(conn, "message_sent", "sender", f"round={token['round_id']}")

    return cursor.lastrowid


'''
Function: get_inbox
Description: SERVER SIDE. Returns the encrypted messages addressed to a
             user. Only roles with read_messages can call this, and only
             their own messages are returned.
Inputs:
    user_id (int): ID of the requesting user.
Returns:
    list: Dicts with message_id, token_id, ciphertext.
'''
def get_inbox(user_id):

    user = get_user(user_id)
    if user is None:
        raise PermissionError("Invalid user.")
    require_permission(user["role"], "read_messages")

    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT message_id, token_id, ciphertext
            FROM messages
            WHERE recipient_id = ?
            ORDER BY message_id
            """,
            (user_id,)
        ).fetchall()

        log_event(conn, "messages_delivered", "recipient", f"count={len(rows)}")

    return [dict(row) for row in rows]


# =====================================================================
# Client side: these run on the user's device
# =====================================================================

'''
Function: send_message
Description: CLIENT SIDE. Encrypts a message for a recipient and submits
             it with an anonymous token.
Inputs:
    token (dict): Token from request_token.
    recipient_id (int): ID of the recipient.
    text (str): Message text.
Returns:
    int: ID of the stored message.
'''
def send_message(token, recipient_id, text):

    # validate the message
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Message cannot be empty.")
    if len(text) > MAX_MESSAGE_CHARS:
        raise ValueError(f"Message exceeds {MAX_MESSAGE_CHARS} characters.")

    # encrypt locally with the recipient's public key
    public_pem = _get_valid_recipient(recipient_id)
    token_id = compute_token_id(token)
    ciphertext = encrypt_message(
        public_pem, text, _associated_data(recipient_id, token_id)
    )

    # only ciphertext leaves the device
    return submit_message(token, recipient_id, ciphertext)


'''
Function: read_inbox
Description: CLIENT SIDE. Fetches the user's encrypted messages and
             decrypts them with the private key stored on their device.
Inputs:
    user_id (int): ID of the recipient.
Returns:
    list: Dicts with message_id and text. Messages that fail to decrypt
          (tampered or wrong key) have text None and an error field.
'''
def read_inbox(user_id):

    private_key = load_user_private_key(user_id)
    inbox = []

    for msg in get_inbox(user_id):
        try:
            text = decrypt_message(
                private_key,
                msg["ciphertext"],
                _associated_data(user_id, msg["token_id"])
            )
            inbox.append({"message_id": msg["message_id"], "text": text})

        except ValueError as error:
            inbox.append({"message_id": msg["message_id"], "text": None, "error": str(error)})

    return inbox