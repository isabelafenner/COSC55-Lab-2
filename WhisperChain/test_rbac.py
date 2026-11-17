from core.rbac import has_permission, require_permission


# --------------------------------------------------
# EXPECTED ROLE-PERMISSION MATRIX
# (matches the matrix in THREAT_MODEL.md)
# --------------------------------------------------

EXPECTED = {
    "sender": {"send_message"},
    "recipient": {"read_messages", "flag_message"},
    "moderator": {"review_flags", "view_audit_logs", "freeze_token"},
    "admin": {"register_user", "assign_roles", "manage_public_keys",
              "manage_policies", "advance_round", "reset_passwords"},
}

ALL_PERMISSIONS = set().union(*EXPECTED.values())


# --------------------------------------------------
# TEST 1: EVERY ROLE HAS EXACTLY ITS PERMISSIONS
# --------------------------------------------------

print("\nTest 1: Full permission matrix")

for role, allowed in EXPECTED.items():

    wrong = [
        action for action in sorted(ALL_PERMISSIONS)
        if has_permission(role, action) != (action in allowed)
    ]

    if wrong:
        print(f"FAIL: {role} has wrong access to {', '.join(wrong)}")
    else:
        print(f"PASS: {role} has exactly {len(allowed)} permission(s)")


# --------------------------------------------------
# TEST 2: SEPARATION OF DUTIES
# --------------------------------------------------

print("\nTest 2: Separation of duties")

checks = [
    ("admin", "read_messages", "Admin cannot read messages"),
    ("admin", "review_flags", "Admin cannot review flags"),
    ("admin", "view_audit_logs", "Admin cannot view audit logs"),
    ("moderator", "read_messages", "Moderator cannot read unflagged messages"),
    ("moderator", "register_user", "Moderator cannot register users"),
    ("recipient", "send_message", "Recipient cannot send messages"),
    ("sender", "read_messages", "Sender cannot read messages"),
]

for role, action, description in checks:
    print(("FAIL: " if has_permission(role, action) else "PASS: ") + description)


# --------------------------------------------------
# TEST 3: UNKNOWN ROLES AND ACTIONS
# --------------------------------------------------

print("\nTest 3: Unknown roles and actions")

if has_permission("superuser", "send_message"):
    print("FAIL: Unknown role has permissions")
else:
    print("PASS: Unknown role has no permissions")

if has_permission("admin", "delete_everything"):
    print("FAIL: Unknown action allowed")
else:
    print("PASS: Unknown action denied")


# --------------------------------------------------
# TEST 4: ENFORCEMENT RAISES AN EXCEPTION
# --------------------------------------------------

print("\nTest 4: require_permission")

try:
    require_permission("sender", "freeze_token")
    print("FAIL: Unauthorized action allowed")
except PermissionError:
    print("PASS: Unauthorized action rejected")

try:
    require_permission("moderator", "freeze_token")
    print("PASS: Authorized action allowed")
except PermissionError:
    print("FAIL: Authorized action rejected")