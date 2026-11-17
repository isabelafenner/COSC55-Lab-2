########## imports ##########
import sqlite3

from database.db import get_connection
from core.users import get_user
from core.rbac import require_permission
from core.rounds import get_current_round
from core.crypto import decrypt_with_message_key
from core.audit import log_event


'''
OVERVIEW: Flagging, moderator review, and alerts

    Flagging (recipient):
        Messages are end-to-end encrypted, so a Moderator can't read them.
        When flagging, the Recipient reveals that ONE message's one-time
        key (not their private key). The server checks the key really
        decrypts the stored ciphertext, so a Recipient can't fake the
        content of a message they're reporting.

    Review (moderator):
        Moderators see only flagged messages, decrypted with the revealed
        key, plus the anonymous token that sent them. They mark each flag
        upheld or dismissed, and can freeze the token (core/tokens.py).
        They never see who sent a message.

    Alerts (automatic):
        Rules run after relevant events and raise at most one alert per
        rule per round:
          - flag_volume:      many messages flagged in one round
          - token_rejections: many failed token uses in one round
                              (possible forgery or replay attempts)
'''


MAX_REASON_CHARS = 500
FLAG_VOLUME_THRESHOLD = 3
TOKEN_REJECTION_THRESHOLD = 5


'''
Function: _require_role_permission
Description: Verifies a user exists and has a permission.
Returns:
    dict: The user record.
'''
def _require_role_permission(user_id, action):

    user = get_user(user_id)

    if user is None:
        raise ValueError("User does not exist.")

    require_permission(user["role"], action)

    return user


# =====================================================================
# Flagging (recipient)
# =====================================================================

'''
Function: submit_flag
Description:
    Server side. Records a Recipient's report of an abusive message.
    The revealed key must decrypt the stored message, which proves the
    reported content is what was actually sent.

Inputs:
    recipient_id (int): ID of the Recipient flagging the message.
    message_id (int): ID of the message being flagged.
    revealed_key (str): The message's one-time key.
    reason (str): Optional explanation from the Recipient.

Returns:
    int: ID of the new flag.

Raises:
    PermissionError: If the user cannot flag messages.
    ValueError: Message not found, key mismatch, or already flagged.
'''
def submit_flag(recipient_id, message_id, revealed_key, reason=None):

    _require_role_permission(recipient_id, "flag_message")

    if reason is not None and len(reason) > MAX_REASON_CHARS:
        raise ValueError(f"Reason exceeds {MAX_REASON_CHARS} characters.")

    with get_connection() as conn:

        # Recipients can only flag messages in their own inbox
        message = conn.execute(
            """
            SELECT ciphertext, round_id
            FROM messages
            WHERE message_id = ? AND recipient_id = ?
            """,
            (message_id, recipient_id)
        ).fetchone()

        if message is None:
            raise ValueError("Message not found for this Recipient.")

        # prove the revealed key belongs to this exact stored message
        decrypt_with_message_key(message["ciphertext"], revealed_key)

        try:
            cursor = conn.execute(
                """
                INSERT INTO flags (message_id, reason, revealed_key)
                VALUES (?, ?, ?)
                """,
                (message_id, reason, revealed_key)
            )

        except sqlite3.IntegrityError as error:
            raise ValueError("Message has already been flagged.") from error

        flag_id = cursor.lastrowid

        log_event(conn, "message_flagged", "recipient", f"round={message['round_id']}")

    check_alert_rules()

    return flag_id


# =====================================================================
# Review (moderator)
# =====================================================================

'''
Function: get_flag_queue
Description:
    Retrieves flagged messages for Moderator review, decrypted with the
    key each Recipient revealed. Never includes Sender information.

Inputs:
    moderator_id (int): ID of the Moderator.
    status (str): "pending" (default), "upheld", or "dismissed".

Returns:
    list: Dicts with flag_id, message_id, token_id, round_id,
          reason, status, flagged_at, and content.
'''
def get_flag_queue(moderator_id, status="pending"):

    _require_role_permission(moderator_id, "review_flags")

    if status not in ("pending", "upheld", "dismissed"):
        raise ValueError("Invalid flag status.")

    with get_connection() as conn:

        rows = conn.execute(
            """
            SELECT f.flag_id, f.message_id, m.token_id, m.round_id,
                   f.reason, f.status, f.flagged_at,
                   f.revealed_key, m.ciphertext
            FROM flags f
            JOIN messages m ON m.message_id = f.message_id
            WHERE f.status = ?
            ORDER BY f.flag_id
            """,
            (status,)
        ).fetchall()

        log_event(conn, "flag_queue_viewed", "moderator", f"count={len(rows)}")

    queue = []

    for row in rows:
        entry = dict(row)

        # decrypt only this flagged message, then drop the key and ciphertext
        entry["content"] = decrypt_with_message_key(
            entry.pop("ciphertext"),
            entry.pop("revealed_key")
        )

        queue.append(entry)

    return queue


'''
Function: review_flag
Description:
    Records a Moderator's decision on a pending flag. To act on an
    upheld flag, the Moderator can then call freeze_token with the
    flag's token_id.

Inputs:
    moderator_id (int): ID of the Moderator.
    flag_id (int): ID of the flag.
    decision (str): "upheld" or "dismissed".

Returns:
    bool: True if the flag was reviewed.

Raises:
    ValueError: Invalid decision, or flag missing or already reviewed.
'''
def review_flag(moderator_id, flag_id, decision):

    _require_role_permission(moderator_id, "review_flags")

    if decision not in ("upheld", "dismissed"):
        raise ValueError("Decision must be 'upheld' or 'dismissed'.")

    with get_connection() as conn:

        # only pending flags can be reviewed, and only once
        cursor = conn.execute(
            """
            UPDATE flags
            SET status = ?, reviewed_at = CURRENT_TIMESTAMP
            WHERE flag_id = ? AND status = 'pending'
            """,
            (decision, flag_id)
        )

        if cursor.rowcount != 1:
            raise ValueError("Flag not found or already reviewed.")

        log_event(conn, f"flag_{decision}", "moderator", f"flag={flag_id}")

    return True


# =====================================================================
# Alerts (automatic)
# =====================================================================

'''
Function: check_alert_rules
Description:
    Evaluates the alert rules for the current round and raises any
    new alerts. Each rule fires at most once per round.

Returns:
    list: Names of rules that raised a new alert.
'''
def check_alert_rules():

    round_id = get_current_round()
    raised = []

    with get_connection() as conn:

        # Rule 1: many messages flagged this round
        flag_count = conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM flags f
            JOIN messages m ON m.message_id = f.message_id
            WHERE m.round_id = ?
            """,
            (round_id,)
        ).fetchone()["n"]

        # Rule 2: many failed token uses this round
        rejection_count = conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM audit_log
            WHERE action = 'token_rejected' AND details = ?
            """,
            (f"round={round_id}",)
        ).fetchone()["n"]

        rules = [
            ("flag_volume", flag_count, FLAG_VOLUME_THRESHOLD),
            ("token_rejections", rejection_count, TOKEN_REJECTION_THRESHOLD),
        ]

        for rule, count, threshold in rules:

            if count < threshold:
                continue

            # one alert per rule per round (also enforced by UNIQUE)
            exists = conn.execute(
                "SELECT 1 FROM alerts WHERE rule = ? AND round_id = ?",
                (rule, round_id)
            ).fetchone()

            if exists:
                continue

            conn.execute(
                """
                INSERT INTO alerts (rule, round_id, details)
                VALUES (?, ?, ?)
                """,
                (rule, round_id, f"count={count} threshold={threshold}")
            )

            log_event(conn, "alert_raised", "system", f"rule={rule} round={round_id}")
            raised.append(rule)

    return raised


'''
Function: get_alerts
Description: Retrieves raised alerts, newest first. Moderators only.

Inputs:
    moderator_id (int): ID of the Moderator.

Returns:
    list: Dicts with alert_id, rule, round_id, details, created_at.
'''
def get_alerts(moderator_id):

    _require_role_permission(moderator_id, "review_flags")

    with get_connection() as conn:
        alerts = conn.execute(
            """
            SELECT alert_id, rule, round_id, details, created_at
            FROM alerts
            ORDER BY alert_id DESC
            """
        ).fetchall()

    return [dict(alert) for alert in alerts]