########## imports ##########
from database.db import get_connection, BASE_DIR
from core.rbac import require_permission
from core.users import get_user
from core.audit import log_event
from core.crypto import generate_keypair, load_public_key, load_private_key


'''
OVERVIEW: Where keys live

    Public keys  -> server database (users.public_key), readable by anyone.
    Private keys -> the USER'S device only. The server never receives them.

    In this project the "device" is simulated by the client_keys/ folder,
    which is kept separate from data/ (the server's storage) on purpose.
'''


# simulated client-side key storage (one file per user)
CLIENT_KEY_DIR = BASE_DIR / "client_keys"


'''
Function: _private_key_path
Description: Location of a user's private key on their (simulated) device.
'''
def _private_key_path(user_id):
    return CLIENT_KEY_DIR / f"user_{user_id}.pem"


# =====================================================================
# Server side
# =====================================================================

'''
Function: register_public_key
Description: SERVER SIDE. Stores a user's public key. A user can only set
             their key once; replacing it requires an admin reset. This
             stops an attacker who hijacks a session from silently swapping
             in their own key to read future messages.
Inputs:
    user_id (int): ID of the user.
    public_pem (bytes or str): PEM public key.
Raises:
    PermissionError: Invalid user, or a key is already registered.
    ValueError: Malformed or weak key.
'''
def register_public_key(user_id, public_pem):

    user = get_user(user_id)
    if user is None:
        raise PermissionError("Invalid user.")

    # validate the key before storing it
    load_public_key(public_pem)
    if isinstance(public_pem, bytes):
        public_pem = public_pem.decode()

    with get_connection() as conn:

        # only set the key if none exists yet (atomic check-and-set)
        cursor = conn.execute(
            """
            UPDATE users SET public_key = ?
            WHERE user_id = ? AND public_key IS NULL
            """,
            (public_pem, user_id)
        )

        if cursor.rowcount == 0:
            raise PermissionError("Public key already registered. Ask an admin to reset it.")

        log_event(conn, "public_key_registered", user["role"])


'''
Function: reset_public_key
Description: SERVER SIDE. Clears a user's public key (e.g. lost device)
             so they can register a new one. Admins can clear keys but
             cannot set them, so an admin can't insert a key of their own
             and read someone's messages.
Inputs:
    admin_id (int): ID of the administrator.
    user_id (int): ID of the user whose key is cleared.
Returns:
    bool: True if a key was cleared, False otherwise.
'''
def reset_public_key(admin_id, user_id):

    admin = get_user(admin_id)
    if admin is None:
        raise PermissionError("Invalid administrator.")
    require_permission(admin["role"], "manage_public_keys")

    with get_connection() as conn:
        cursor = conn.execute(
            """
            UPDATE users SET public_key = NULL
            WHERE user_id = ? AND public_key IS NOT NULL
            """,
            (user_id,)
        )

        reset = cursor.rowcount > 0
        if reset:
            log_event(conn, "public_key_reset", "admin")

    return reset


'''
Function: get_public_key
Description: Retrieves a user's registered public key.
Inputs:
    user_id (int): ID of the user.
Returns:
    str: PEM public key, or None if not registered.
'''
def get_public_key(user_id):
    user = get_user(user_id)
    return user["public_key"] if user else None


# =====================================================================
# Client side: these run on the user's device
# =====================================================================

'''
Function: setup_user_keys
Description: CLIENT SIDE. Generates the user's key pair, saves the private
             key locally, and registers only the public key with the server.
Inputs:
    user_id (int): ID of the user.
Returns:
    str: PEM public key that was registered.
'''
def setup_user_keys(user_id):

    private_pem, public_pem = generate_keypair()

    # register the public key first. If the server refuses, nothing is saved
    register_public_key(user_id, public_pem)

    # save the private key on the "device" with owner-only permissions
    CLIENT_KEY_DIR.mkdir(parents=True, exist_ok=True)
    path = _private_key_path(user_id)
    path.write_bytes(private_pem)
    path.chmod(0o600)

    return public_pem.decode()


'''
Function: load_user_private_key
Description: CLIENT SIDE. Loads the user's private key from their device.
Inputs:
    user_id (int): ID of the user.
Returns:
    RSAPrivateKey: The user's private key.
Raises:
    FileNotFoundError: If no key is stored for this user.
'''
def load_user_private_key(user_id):

    path = _private_key_path(user_id)
    if not path.exists():
        raise FileNotFoundError(f"No private key on this device for user {user_id}.")

    return load_private_key(path.read_bytes())