########## imports ##########
import json

from core.messages import get_messages, get_message
from core.keys import load_user_private_key, CLIENT_KEY_DIR
from core.crypto import decrypt_message, recover_message_key
from core.moderation import submit_flag


'''
OVERVIEW: Client-side operations

    Everything in this file runs on the Recipient's device.
    The server (core/messages.py) only ever returns ciphertext.
    The private key is loaded from the device and used here,
    so plaintext never exists on the server.
'''


'''
Function: read_message
Description:
    CLIENT SIDE. Fetches one encrypted message from the server and
    decrypts it locally with the Recipient's private key.

Inputs:
    recipient_id (int): ID of the Recipient.
    message_id (int): ID of the message to read.

Returns:
    str: Decrypted plaintext message.
'''
def read_message(recipient_id, message_id):

    # ciphertext from the server
    ciphertext = get_message(recipient_id, message_id)

    # private key from the device
    private_key = load_user_private_key(recipient_id)

    # decrypt on the device
    return decrypt_message(ciphertext, private_key)


'''
Function: read_inbox
Description:
    CLIENT SIDE. Fetches all of the Recipient's encrypted messages
    and decrypts them locally.

Inputs:
    recipient_id (int): ID of the Recipient.

Returns:
    list: Dicts with message_id and decrypted text.
'''
def read_inbox(recipient_id):

    private_key = load_user_private_key(recipient_id)

    return [
        {
            "message_id": message["message_id"],
            "text": decrypt_message(message["ciphertext"], private_key)
        }
        for message in get_messages(recipient_id)
    ]


'''
Function: flag_message
Description:
    CLIENT SIDE. Reports an abusive message to the Moderators.
    Recovers the message's one-time key on the device and sends ONLY
    that key, so Moderators can read this one message. The private
    key never leaves the device.

Inputs:
    recipient_id (int): ID of the Recipient.
    message_id (int): ID of the message to flag.
    reason (str): Optional explanation.

Returns:
    int: ID of the new flag.
'''
def flag_message(recipient_id, message_id, reason=None):

    # ciphertext from the server, private key from the device
    ciphertext = get_message(recipient_id, message_id)
    private_key = load_user_private_key(recipient_id)

    # unwrap this message's key locally
    message_key = recover_message_key(ciphertext, private_key)

    return submit_flag(recipient_id, message_id, message_key, reason)


# =====================================================================
# Token storage on the device
# =====================================================================

'''
Function: save_token
Description:
    CLIENT SIDE. Keeps a Sender's token on their device until it is
    used, so it isn't lost between sessions (a lost token can't be
    reissued in the same round).

Inputs:
    user_id (int): ID of the Sender.
    round_id (int): Round the token belongs to.
    token (str): The anonymous token.
'''
def save_token(user_id, round_id, token):

    CLIENT_KEY_DIR.mkdir(parents=True, exist_ok=True)

    path = _token_path(user_id)
    path.write_text(json.dumps({"round_id": round_id, "token": token}))
    path.chmod(0o600)


'''
Function: load_token
Description:
    CLIENT SIDE. Retrieves the Sender's saved token, if any.

Inputs:
    user_id (int): ID of the Sender.

Returns:
    dict: {"round_id", "token"}, or None if nothing is saved.
'''
def load_token(user_id):

    path = _token_path(user_id)

    if not path.exists():
        return None

    return json.loads(path.read_text())


'''
Function: clear_token
Description: CLIENT SIDE. Removes the saved token once it has been used.

Inputs:
    user_id (int): ID of the Sender.
'''
def clear_token(user_id):
    _token_path(user_id).unlink(missing_ok=True)


'''location of a Sender's saved token on their (simulated) device'''
def _token_path(user_id):
    return CLIENT_KEY_DIR / f"user_{user_id}_token.json"