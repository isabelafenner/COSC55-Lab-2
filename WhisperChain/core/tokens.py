########## imports ##########
import secrets

from database.db import get_connection
from core.users import get_user
from core.rbac import require_permission

import sqlite3

from core.rounds import is_active_round
from core.audit import log_event


'''
Function: issue_token
Description:
    Generates an anonymous token for a Sender in a specific round.
    Each Sender can receive only one token per round.

Inputs:
    user_id (int): ID of the Sender requesting a token.
    round_id (int): Current messaging round.

Returns:
    str: Newly generated anonymous token.
'''
def issue_token(user_id, round_id):

    # verify that the user exists
    user = get_user(user_id)

    if user is None:
        raise ValueError("User does not exist")

    # verify that the user has Sender permissions
    require_permission(user["role"], "send_message")

    # verify that the round ID is valid
    if not isinstance(round_id, int) or round_id <= 0:
        raise ValueError("Round ID must be a positive integer")

    # Reject token requests for inactive rounds
    if not is_active_round(round_id):
        raise ValueError("Cannot issue tokens for an inactive round")

    # generate a cryptographically random token
    token_id = secrets.token_urlsafe(32)

    with get_connection() as conn:

        # record that this Sender has received a token
        # the database prevents duplicate issuance per round
        try:
            conn.execute(
                """
                INSERT INTO token_issuance (user_id, round_id)
                VALUES (?, ?)
                """,
                (user_id, round_id)
            )

        except sqlite3.IntegrityError as error:
            raise ValueError(
                "Sender has already received a token for this round"
            ) from error

        # store the anonymous token separately from the user ID
        conn.execute(
            """
            INSERT INTO tokens (token_id, round_id)
            VALUES (?, ?)
            """,
            (token_id, round_id)
        )

        # log the issuance by role only, never the Sender's identity
        log_event(conn, "token_issued", "sender", f"round={round_id}")

    return token_id


'''
Function: validate_token
Description:
    Checks whether an anonymous token exists, belongs to the
    specified round, and has not been used or frozen.

Inputs:
    token_id (str): Anonymous token identifier.
    round_id (int): Messaging round.

Returns:
    bool: True if the token is valid, False otherwise.
'''
def validate_token(token_id, round_id):

    # reject tokens from previous or future rounds
    if not is_active_round(round_id):
        return False

    with get_connection() as conn:

        token = conn.execute(
            """
            SELECT *
            FROM tokens
            WHERE token_id = ? AND round_id = ?
            """,
            (token_id, round_id)
        ).fetchone()

    # reject nonexistent tokens
    if token is None:
        return False

    # reject tokens that have already been used
    if token["used"] == 1:
        return False

    # reject tokens that have been frozen
    if token["frozen"] == 1:
        return False

    return True


'''
Function: use_token
Description:
    Marks an anonymous token as used.
    Each token can be used only once.

Inputs:
    token_id (str): Anonymous token identifier.
    round_id (int): Messaging round.

Returns:
    bool: True if the token was successfully used,
          False if it was invalid, used, or frozen.
'''
def use_token(token_id, round_id):

    # reject tokens from inactive rounds
    if not is_active_round(round_id):
        return False

    with get_connection() as conn:

        # update the token only if it is unused and unfrozen
        cursor = conn.execute(
            """
            UPDATE tokens
            SET used = 1
            WHERE token_id = ?
              AND round_id = ?
              AND used = 0
              AND frozen = 0
            """,
            (token_id, round_id)
        )

        # exactly one updated row means successful redemption
        used = cursor.rowcount == 1

        log_event(
            conn,
            "token_used" if used else "token_rejected",
            "sender",
            f"round={round_id}"
        )

        return used


'''
Function: freeze_token
Description:
    Allows a Moderator to freeze an anonymous token,
    preventing it from being used in the future.

Inputs:
    moderator_id (int): ID of the Moderator.
    token_id (str): Token to freeze.

Returns:
    bool: True if the token was found and frozen,
          False if the token does not exist.
'''
def freeze_token(moderator_id, token_id):

    # verify that the Moderator exists
    moderator = get_user(moderator_id)

    if moderator is None:
        raise ValueError("User does not exist")

    # verify that the user has permission to freeze tokens
    require_permission(moderator["role"], "freeze_token")

    with get_connection() as conn:

        # freeze the token
        cursor = conn.execute(
            """
            UPDATE tokens
            SET frozen = 1
            WHERE token_id = ?
            """,
            (token_id,)
        )

        frozen = cursor.rowcount == 1

        # log a short prefix of the token, never the full value
        if frozen:
            log_event(conn, "token_frozen", "moderator", f"token={token_id[:8]}")

        return frozen