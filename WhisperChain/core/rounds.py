########## imports ##########
from database.db import get_connection
from core.users import get_user
from core.rbac import require_permission


'''
Function: get_current_round
Description:
    Retrieves the current active messaging round
    from the system_state table.

Inputs:
    None

Returns:
    int: Current active round number.
'''
def get_current_round():

    with get_connection() as conn:

        result = conn.execute(
            """
            SELECT current_round
            FROM system_state
            WHERE state_id = 1
            """
        ).fetchone()

    if result is None:
        raise ValueError("Current round has not been initialized.")

    return result["current_round"]


'''
Function: advance_round
Description:
    Allows an Admin to advance the messaging system
    to the next round.

Inputs:
    admin_id (int): ID of the administrator.

Returns:
    int: New active round number.
'''
def advance_round(admin_id):

    # Verify that the administrator exists
    admin = get_user(admin_id)

    if admin is None:
        raise ValueError("User does not exist.")

    # Verify permission to advance rounds
    require_permission(admin["role"], "advance_round")

    with get_connection() as conn:

        # Increment the current round by one
        conn.execute(
            """
            UPDATE system_state
            SET current_round = current_round + 1
            WHERE state_id = 1
            """
        )

        # Retrieve the updated round number
        result = conn.execute(
            """
            SELECT current_round
            FROM system_state
            WHERE state_id = 1
            """
        ).fetchone()

    if result is None:
        raise ValueError("Current round has not been initialized.")

    return result["current_round"]


'''
Function: is_active_round
Description:
    Checks whether a specified round is currently active.

Inputs:
    round_id (int): Round number to check.

Returns:
    bool: True if the round is active, False otherwise.
'''
def is_active_round(round_id):

    return round_id == get_current_round()
