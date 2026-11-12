
from database.db import initialize_database, get_connection
from core.users import register_user, update_user_role, get_user


# Initialize the database and create tables
initialize_database()


# Create the initial administrator if one does not exist
with get_connection() as conn:

    admin = conn.execute(
        "SELECT user_id FROM users WHERE username = ?",
        ("david",)
    ).fetchone()

    if admin is None:
        cursor = conn.execute(
            """
            INSERT INTO users (username, role)
            VALUES (?, ?)
            """,
            ("david", "admin")
        )
        admin_id = cursor.lastrowid

    else:
        admin_id = admin["user_id"]


# Create a Sender for permission testing
with get_connection() as conn:

    sender = conn.execute(
        "SELECT user_id FROM users WHERE username = ?",
        ("alice",)
    ).fetchone()

    if sender is None:
        sender_id = register_user(admin_id, "alice", "sender")
    else:
        sender_id = sender["user_id"]


# Test 1: Admin registers a new user
print("\nTest 1: Admin registration")

with get_connection() as conn:
    existing = conn.execute(
        "SELECT user_id FROM users WHERE username = ?",
        ("eve",)
    ).fetchone()

if existing is None:
    new_id = register_user(admin_id, "eve", "sender")
else:
    new_id = existing["user_id"]

print("New user:", get_user(new_id))


# Test 2: Sender attempts to register a user
print("\nTest 2: Unauthorized registration")

try:
    register_user(sender_id, "frank", "sender")
    print("FAIL: Sender registered a user")

except PermissionError:
    print("PASS: Sender cannot register users")


# Test 3: Admin changes a user's role
print("\nTest 3: Admin role update")

update_user_role(admin_id, new_id, "recipient")

print("Updated user:", get_user(new_id))


# Test 4: Recipient attempts to change a role
print("\nTest 4: Unauthorized role update")

try:
    update_user_role(new_id, sender_id, "admin")
    print("FAIL: Recipient changed a role")

except PermissionError:
    print("PASS: Recipient cannot change roles")
