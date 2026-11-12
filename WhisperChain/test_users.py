from database.db import initialize_database
from core.users import register_user, get_user, get_all_users


# Ensure the database exists
initialize_database()

# Register example users
'''
register_user("alice", "sender")
register_user("bob", "recipient")
register_user("charlie", "moderator")
register_user("david", "admin")
'''

# Retrieve one user
print("Single user:")
print(get_user(1))

# Retrieve all users
print("\nAll users:")
for user in get_all_users():
    print(user)
