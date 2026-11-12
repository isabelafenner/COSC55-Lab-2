########## imports ##########
from database.db import get_connection
from core.rbac import require_permission


'''
Function: register_user
Description: Registers a new user in the database with an assigned role.
Inputs:
    username (str): Username of the new user.
    role (str): Assigned role (sender, recipient, moderator, admin).
Returns:
    int: Unique ID of the newly registered user.
'''
def register_user(admin_id, username, role):

    # Retrieve the administrator's information
    admin = get_user(admin_id)

    # Reject nonexistent users
    if admin is None:
        raise PermissionError("Invalid administrator.")

    # Verify administrator permissions
    require_permission(admin["role"], "register_user")

    # validate username
    if not isinstance(username, str) or not username.strip():
        raise ValueError("Username cannot be empty")

    # connect to the database
    with get_connection() as conn:

        # insert a new user with the provided username and role
        cursor = conn.execute(
            """
            INSERT INTO users (username, role)
            VALUES (?, ?)
            """,
            (username, role)
        )

        # return the automatically generated user ID
        return cursor.lastrowid


'''
Function: get_user
Description: Retrieves a user from the database using their unique ID.
Inputs:
    user_id (int): Unique identifier of the user.
Returns:
    dict: User information if found.
    None: If no user exists with the provided ID.
'''
def get_user(user_id):

    # connect to the database
    with get_connection() as conn:

        # search for the user with the matching ID
        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE user_id = ?
            """,
            (user_id,)
        ).fetchone()

    # convert the SQLite row into a dictionary, or return None
    return dict(user) if user else None


'''
Function: get_all_users
Description: Retrieves all registered users from the database.
Inputs:
    None
Returns:
    list: List of dictionaries containing user information.
'''
def get_all_users():

    # connect to the database
    with get_connection() as conn:

        # retrieve all rows from the users table
        users = conn.execute(
            """
            SELECT *
            FROM users
            """
        ).fetchall()

    # convert each SQLite row into a dictionary
    return [dict(user) for user in users]


'''
Function: update_user_role
Description: Changes a user's assigned role.
             Only administrators can modify roles.
Inputs:
    admin_id (int): ID of the administrator.
    user_id (int): ID of the user being modified.
    new_role (str): New role to assign.
Returns:
    bool: True if updated, False if user does not exist.
'''
def update_user_role(admin_id, user_id, new_role):

    # Retrieve administrator information
    admin = get_user(admin_id)

    if admin is None:
        raise PermissionError("Invalid administrator.")

    # Verify permission to assign roles
    require_permission(admin["role"], "assign_roles")

    # Update user role
    with get_connection() as conn:
        cursor = conn.execute(
            """
            UPDATE users
            SET role = ?
            WHERE user_id = ?
            """,
            (new_role, user_id)
        )

        return cursor.rowcount > 0
