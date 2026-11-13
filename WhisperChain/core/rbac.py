# define the permissions associated with each role
ROLE_PERMISSIONS = {
    "sender": {
        "send_message"
    },
    "recipient": {
        "read_messages",
        "flag_message"
    },
    "moderator": {
        "review_flags",
        "view_audit_logs",
        "freeze_token"
    },
    "admin": {
        "register_user",
        "assign_roles",
        "manage_public_keys",
        "manage_policies",
        "advance_round"
    }
}


'''
Function: has_permission
Description: Determines whether a user role has permission
             to perform a specified action.
Inputs:
    role (str): Role of the user.
    action (str): Action the user wants to perform.
Returns:
    bool: True if permitted, False otherwise.
'''
def has_permission(role, action):

    # retrieve the permissions associated with the role
    # return an empty set if the role does not exist
    permissions = ROLE_PERMISSIONS.get(role, set())

    # check whether the requested action is permitted
    return action in permissions


'''
Function: require_permission
Description: Enforces role-based access control by raising
             an exception when an action is unauthorized.
Inputs:
    role (str): Role of the user.
    action (str): Action the user wants to perform.
Returns:
    None: If the action is permitted.
Raises:
    PermissionError: If the action is not permitted.
'''
def require_permission(role, action):

    # check whether the role is authorized
    if not has_permission(role, action):
        raise PermissionError(
            f"Role '{role}' cannot perform '{action}'."
        )
