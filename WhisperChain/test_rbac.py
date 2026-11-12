
from core.rbac import has_permission, require_permission


# Test 1: Sender can send messages
print(has_permission("sender", "send_message"))

# Test 2: Recipient cannot send messages
print(has_permission("recipient", "send_message"))

# Test 3: Moderator can review flagged messages
print(has_permission("moderator", "review_flags"))

# Test 4: Admin cannot review flagged messages
print(has_permission("admin", "review_flags"))

# Test 5: Invalid role has no permissions
print(has_permission("superuser", "send_message"))

# Test 6: Unauthorized action raises an exception
try:
    require_permission("sender", "freeze_token")
    print("FAIL: Unauthorized action allowed")

except PermissionError:
    print("PASS: Unauthorized action rejected")
