########## imports ##########
from database.db import get_connection
from core.users import get_user
from core.rbac import require_permission
from core.crypto import encrypt_message
from core.audit import log_event


'''
Function: send_message
Description:
    Encrypts and submits an anonymous message using a valid token.
    Stores the message and consumes the token in one transaction.

Inputs:
    token_id (str): Anonymous messaging token.
    recipient_id (int): ID of the intended Recipient.
    plaintext (str): Message to send.

Returns:
    int: ID of the newly created message.
'''
def send_message(token_id, recipient_id, plaintext):

    # verify the intended Recipient exists and has the correct role
    recipient = get_user(recipient_id)

    if recipient is None:
        raise ValueError("Recipient does not exist.")

    if recipient["role"] != "recipient":
        raise ValueError("User is not a Recipient.")

    # verify that the Recipient has a public encryption key
    if not recipient["public_key"]:
        raise ValueError("Recipient does not have a public key.")

    # reject empty messages
    if not isinstance(plaintext, str) or not plaintext.strip():
        raise ValueError("Message cannot be empty.")

    # encrypt before storing anything in the database
    ciphertext = encrypt_message(
        plaintext,
        recipient["public_key"]
    )

    with get_connection() as conn:

        # begin a write transaction so round checks, token
        # redemption, and message storage happen atomically
        conn.execute("BEGIN IMMEDIATE")

        # retrieve the active messaging round
        round_record = conn.execute(
            """
            SELECT current_round
            FROM system_state
            WHERE state_id = 1
            """
        ).fetchone()

        if round_record is None:
            raise ValueError("Active round is not initialized.")

        current_round = round_record["current_round"]

        # consume a token only if it belongs to the active round,
        # has not been used, and has not been frozen
        cursor = conn.execute(
            """
            UPDATE tokens
            SET used = 1
            WHERE token_id = ?
              AND round_id = ?
              AND used = 0
              AND frozen = 0
            """,
            (token_id, current_round)
        )

        if cursor.rowcount != 1:

            # undo the open transaction, then record the rejection
            # separately so the log entry survives
            conn.rollback()
            log_event(conn, "token_rejected", "sender", f"round={current_round}")
            conn.commit()

            # imported here to avoid a circular import
            from core.moderation import check_alert_rules
            check_alert_rules()

            raise ValueError("Token is invalid, expired, used, or frozen.")

        # store the encrypted message without a Sender ID
        cursor = conn.execute(
            """
            INSERT INTO messages (
                recipient_id,
                token_id,
                round_id,
                ciphertext
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                recipient_id,
                token_id,
                current_round,
                ciphertext
            )
        )

        message_id = cursor.lastrowid

        # log the send by role only, never the Sender or the content
        log_event(conn, "message_sent", "sender", f"round={current_round}")

    return message_id


'''
Function: get_messages
Description:
    Retrieves encrypted messages belonging to a Recipient.
    Does not decrypt the message contents.

Inputs:
    recipient_id (int): ID of the Recipient.

Returns:
    list: Encrypted message records.
'''
def get_messages(recipient_id):

    # verify the user exists
    recipient = get_user(recipient_id)

    if recipient is None:
        raise ValueError("User does not exist.")

    # verify Recipient permissions
    require_permission(recipient["role"], "read_messages")

    with get_connection() as conn:

        messages = conn.execute(
            """
            SELECT message_id, round_id, ciphertext
            FROM messages
            WHERE recipient_id = ?
            ORDER BY message_id
            """,
            (recipient_id,)
        ).fetchall()

        log_event(conn, "messages_delivered", "recipient", f"count={len(messages)}")

    return [dict(message) for message in messages]


'''
Function: get_message
Description:
    SERVER SIDE. Retrieves one encrypted message belonging to a
    Recipient. Returns ciphertext only: the server never sees the
    private key and never decrypts. Decryption happens on the
    Recipient's device (see core/client.py).

Inputs:
    recipient_id (int): ID of the Recipient.
    message_id (int): ID of the message to retrieve.

Returns:
    str: Encrypted message (ciphertext).
'''
def get_message(recipient_id, message_id):

    # verify the user exists
    recipient = get_user(recipient_id)

    if recipient is None:
        raise ValueError("User does not exist.")

    # verify Recipient permissions
    require_permission(recipient["role"], "read_messages")

    with get_connection() as conn:

        # retrieve only messages belonging to this Recipient
        message = conn.execute(
            """
            SELECT ciphertext
            FROM messages
            WHERE message_id = ?
              AND recipient_id = ?
            """,
            (message_id, recipient_id)
        ).fetchone()

        if message is not None:
            log_event(conn, "message_read", "recipient")

    if message is None:
        raise ValueError("Message not found for this Recipient.")

    # return ciphertext only
    return message["ciphertext"]