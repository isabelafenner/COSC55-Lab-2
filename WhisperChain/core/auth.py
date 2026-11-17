########## imports ##########
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from database.db import get_connection
from core.rbac import require_permission
from core.audit import log_event


'''
OVERVIEW: Password authentication

    STORAGE
        Passwords are hashed with scrypt, a deliberately slow, memory-hard
        function, using a fresh random salt per password. Only the hash is
        stored, in users.password_hash. Passwords never appear in the
        database or the audit log.

    NEW ACCOUNTS
        Every new or reset account starts with the same default password
        (DEFAULT_PASSWORD) and must replace it at first login. Admins never
        learn the password a user chooses.
        Risk: anyone who knows the default can log in as an account that
        hasn't logged in yet (see THREAT_MODEL.md, T18).

    BRUTE FORCE
        5 wrong passwords in a row lock the account for 5 minutes.

    USERNAME ENUMERATION
        A wrong username and a wrong password return the same error, and a
        wrong username still runs a full scrypt check so the response time
        doesn't give it away.
'''


MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 5

# scrypt cost parameters (N, r, p): ~16 MB of memory per hash
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1

GENERIC_LOGIN_ERROR = "Invalid username or password."

# given to every new or reset account; must be changed at first login
DEFAULT_PASSWORD = "changeme1"


# =====================================================================
# Hashing
# =====================================================================

'''
Function: hash_password
Description: Hashes a password with scrypt and a new random salt.
Inputs:
    password (str): Plaintext password.
Returns:
    str: "scrypt$N$r$p$salt$hash", everything needed to verify it later.
'''
def hash_password(password):

    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P
    )

    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


'''
Function: verify_password
Description: Checks a password against a stored hash in constant time.
Inputs:
    password (str): Password to check.
    stored (str): Value from hash_password.
Returns:
    bool: True if the password matches.
'''
def verify_password(password, stored):

    try:
        _, n, r, p, salt_hex, digest_hex = stored.split("$")
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex), n=int(n), r=int(r), p=int(p)
        )
    except (ValueError, AttributeError):
        return False

    return hmac.compare_digest(digest.hex(), digest_hex)


# used when a username doesn't exist, so the check takes the same time
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


# =====================================================================
# Helpers
# =====================================================================

'''current UTC time as stored in the database'''
def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _format(moment):
    return moment.strftime("%Y-%m-%d %H:%M:%S")


'''reject passwords that are too short, too long, or not text'''
def _validate_new_password(password):

    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")

    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters.")


'''load the login fields for one user (by ID or username), or None'''
def _get_credentials(conn, user_id=None, username=None):

    column, value = ("user_id", user_id) if user_id is not None else ("username", username)

    return conn.execute(
        f"""
        SELECT user_id, username, role, password_hash,
               must_change_password, failed_logins, locked_until
        FROM users
        WHERE {column} = ?
        """,
        (value,)
    ).fetchone()


# =====================================================================
# Setting passwords
# =====================================================================

'''
Function: set_password
Description: Stores a new password for a user and clears any lockout.
             Used for the first admin and by change_password; the CLI
             only reaches it after the user is authenticated.
Inputs:
    user_id (int): ID of the user.
    password (str): New plaintext password.
    must_change (bool): True if the user must replace it at next login.
'''
def set_password(user_id, password, must_change=False):

    _validate_new_password(password)

    with get_connection() as conn:
        cursor = conn.execute(
            """
            UPDATE users
            SET password_hash = ?, must_change_password = ?,
                failed_logins = 0, locked_until = NULL
            WHERE user_id = ?
            """,
            (hash_password(password), int(must_change), user_id)
        )

        if cursor.rowcount != 1:
            raise ValueError("User does not exist.")


'''
Function: assign_default_password
Description: Sets a user's password to the shared default and requires
             them to change it at first login. Used when an Admin registers
             a user or resets a forgotten password. Only Admins can do this.
Inputs:
    admin_id (int): ID of the administrator.
    user_id (int): ID of the user.
Returns:
    str: The default password, to tell the user.
'''
def assign_default_password(admin_id, user_id):

    with get_connection() as conn:
        admin = _get_credentials(conn, user_id=admin_id)
        target = _get_credentials(conn, user_id=user_id)

    if admin is None:
        raise PermissionError("Invalid administrator.")

    require_permission(admin["role"], "reset_passwords")

    if target is None:
        raise ValueError("User does not exist.")

    set_password(user_id, DEFAULT_PASSWORD, must_change=True)

    with get_connection() as conn:
        log_event(conn, "password_reset", "admin", f"role={target['role']}")

    return DEFAULT_PASSWORD


'''
Function: change_password
Description: Lets a logged-in user replace their password. The current
             password is required, so a session left open can't be used
             to take over the account.
Inputs:
    user_id (int): ID of the user.
    current_password (str): Their current password.
    new_password (str): The replacement.
Raises:
    PermissionError: If the current password is wrong.
    ValueError: If the new password is invalid or unchanged.
'''
def change_password(user_id, current_password, new_password):

    with get_connection() as conn:
        user = _get_credentials(conn, user_id=user_id)

    if user is None or not verify_password(current_password, user["password_hash"]):
        raise PermissionError("Current password is incorrect.")

    if current_password == new_password:
        raise ValueError("New password must be different from the current one.")

    set_password(user_id, new_password, must_change=False)

    with get_connection() as conn:
        log_event(conn, "password_changed", user["role"])


# =====================================================================
# Logging in
# =====================================================================

'''
Function: authenticate
Description: Checks a username and password.
Inputs:
    username (str): Username entered.
    password (str): Password entered.
Returns:
    dict: user_id, username, role, must_change_password.
Raises:
    PermissionError: Wrong username or password (same message for both),
                     or the account is locked.
'''
def authenticate(username, password):

    with get_connection() as conn:
        user = _get_credentials(conn, username=username)

    # unknown user or no password set: same work, same error
    if user is None or user["password_hash"] is None:
        verify_password(password, _DUMMY_HASH)

        with get_connection() as conn:
            log_event(conn, "login_failed", user["role"] if user else "unknown")

        raise PermissionError(GENERIC_LOGIN_ERROR)

    # refuse while locked, without checking the password
    if user["locked_until"]:
        locked_until = datetime.strptime(user["locked_until"], "%Y-%m-%d %H:%M:%S")

        if _now() < locked_until:
            minutes = int((locked_until - _now()).total_seconds() // 60) + 1
            raise PermissionError(
                f"Account locked after too many failed attempts. "
                f"Try again in {minutes} minute(s)."
            )

    if not verify_password(password, user["password_hash"]):

        failures = user["failed_logins"] + 1
        locked_until = None

        if failures >= MAX_FAILED_LOGINS:
            locked_until = _format(_now() + timedelta(minutes=LOCKOUT_MINUTES))
            failures = 0

        with get_connection() as conn:
            conn.execute(
                "UPDATE users SET failed_logins = ?, locked_until = ? WHERE user_id = ?",
                (failures, locked_until, user["user_id"])
            )
            log_event(conn, "login_failed", user["role"])

            if locked_until:
                log_event(conn, "account_locked", user["role"], f"minutes={LOCKOUT_MINUTES}")

        raise PermissionError(GENERIC_LOGIN_ERROR)

    # success: reset the failure count
    with get_connection() as conn:
        conn.execute(
            "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE user_id = ?",
            (user["user_id"],)
        )
        log_event(conn, "login_success", user["role"])

    return {
        "user_id": user["user_id"],
        "username": user["username"],
        "role": user["role"],
        "must_change_password": bool(user["must_change_password"]),
    }