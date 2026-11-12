########## imports ##########
import hashlib
import secrets
import sqlite3
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from database.db import get_connection, BASE_DIR
from core.rbac import require_permission
from core.users import get_user
from core.audit import log_event


'''
OVERVIEW: Anonymous, unlinkable message tokens via RSA blind signatures

    1. CLIENT  picks a random serial and blinds it with a random factor r.
    2. SERVER  checks the requester is a Sender who hasn't had a token this
               round, records (user_id, round_id), and signs the BLINDED
               value. It never sees the serial.
    3. CLIENT  removes r, leaving a valid signature on the serial.
    4. Later, anyone holding (round_id, serial, signature) can redeem it.
       The server verifies the signature, but it cannot match the token to
       the blinded value it signed, so it cannot tell who the sender was.

    Unlinkability holds against the server itself, not just against
    other users.
'''


# location of the system's token-signing key
TOKEN_KEY_PATH = BASE_DIR / "data" / "token_signing_key.pem"
RSA_KEY_SIZE = 2048


# =====================================================================
# Key management
# =====================================================================

'''
Function: _load_signing_key
Description: Loads the system's RSA token-signing key, generating it
             on first use. This key is used ONLY for tokens.
Returns:
    RSAPrivateKey: The token-signing private key.
'''
def _load_signing_key():

    # generate and save a new key if none exists
    if not TOKEN_KEY_PATH.exists():
        TOKEN_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE
        )
        TOKEN_KEY_PATH.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
        TOKEN_KEY_PATH.chmod(0o600)
        return key

    # otherwise load the existing key
    return serialization.load_pem_private_key(
        TOKEN_KEY_PATH.read_bytes(),
        password=None
    )


'''
Function: get_public_key_numbers
Description: Returns the public (n, e) that clients need for blinding
             and anyone needs for verification.
Returns:
    tuple: (n, e) as integers.
'''
def get_public_key_numbers():
    public = _load_signing_key().public_key().public_numbers()
    return public.n, public.e


# =====================================================================
# Helpers
# =====================================================================

'''
Function: _hash_to_int
Description: Full-domain hash of a token's contents to an integer mod n.
             Binding the round_id into the hash means a token is only
             valid for the round it was issued in.
Inputs:
    round_id (int): Round the token belongs to.
    serial (str): Random hex serial chosen by the client.
    n (int): RSA modulus.
Returns:
    int: Hash value in the range [0, n).
'''
def _hash_to_int(round_id, serial, n):
    data = f"whisperchain-token|{round_id}|{serial}".encode()
    num_bytes = (n.bit_length() + 7) // 8
    digest = hashlib.shake_256(data).digest(num_bytes)
    return int.from_bytes(digest, "big") % n


'''
Function: compute_token_id
Description: Derives the public identifier of a token. This is what is
             stored, attached to messages, and frozen by moderators.
Inputs:
    token (dict): Token with keys round_id, serial, signature.
Returns:
    str: SHA-256 hex digest identifying the token.
'''
def compute_token_id(token):
    data = f"{token['round_id']}|{token['serial']}".encode()
    return hashlib.sha256(data).hexdigest()


# =====================================================================
# Rounds
# =====================================================================

'''
Function: get_current_round
Description: Retrieves the ID of the active messaging round.
Returns:
    int: Active round ID.
Raises:
    RuntimeError: If no round is active.
'''
def get_current_round():

    with get_connection() as conn:
        row = conn.execute(
            "SELECT round_id FROM rounds WHERE is_active = 1"
        ).fetchone()

    if row is None:
        raise RuntimeError("No active round.")

    return row["round_id"]


'''
Function: start_new_round
Description: Closes the current round and opens a new one. Tokens from
             earlier rounds can no longer be redeemed.
             Only administrators can rotate rounds.
Inputs:
    admin_id (int): ID of the administrator.
Returns:
    int: ID of the new round.
'''
def start_new_round(admin_id):

    # verify administrator permissions
    admin = get_user(admin_id)
    if admin is None:
        raise PermissionError("Invalid administrator.")
    require_permission(admin["role"], "manage_policies")

    with get_connection() as conn:

        # close the current round, then open a new one
        conn.execute("UPDATE rounds SET is_active = 0 WHERE is_active = 1")
        cursor = conn.execute("INSERT INTO rounds (is_active) VALUES (1)")
        round_id = cursor.lastrowid

        log_event(conn, "round_started", "admin", f"round={round_id}")

    return round_id


# =====================================================================
# Client side: these run on the sender's device
# =====================================================================

'''
Function: blind_token
Description: CLIENT SIDE. Creates a random token serial and blinds it
             so the server can sign it without seeing it.
Inputs:
    round_id (int): Round the token is for.
Returns:
    tuple: (blinded_message, secret_state)
        blinded_message (int): Value sent to the server for signing.
        secret_state (dict): Kept private by the client for unblinding.
'''
def blind_token(round_id):

    n, e = get_public_key_numbers()

    # random serial: the token's unique identity
    serial = secrets.token_hex(32)
    m = _hash_to_int(round_id, serial, n)

    # random blinding factor r, which must be invertible mod n
    while True:
        r = secrets.randbelow(n - 2) + 2
        try:
            r_inv = pow(r, -1, n)
            break
        except ValueError:
            continue

    # blinded = m * r^e mod n
    blinded_message = (m * pow(r, e, n)) % n

    secret_state = {
        "round_id": round_id,
        "serial": serial,
        "r_inv": r_inv
    }

    return blinded_message, secret_state


'''
Function: unblind_signature
Description: CLIENT SIDE. Removes the blinding factor from the server's
             signature, producing a valid signature on the real token.
Inputs:
    blind_signature (int): Signature returned by the server.
    secret_state (dict): State saved by blind_token.
Returns:
    dict: Finished token {round_id, serial, signature}.
'''
def unblind_signature(blind_signature, secret_state):

    n, _ = get_public_key_numbers()

    # signature = blind_signature * r^-1 mod n
    signature = (blind_signature * secret_state["r_inv"]) % n

    return {
        "round_id": secret_state["round_id"],
        "serial": secret_state["serial"],
        "signature": signature
    }


# =====================================================================
# Server side
# =====================================================================

'''
Function: issue_blind_signature
Description: SERVER SIDE. Signs a blinded token for a Sender, enforcing
             one token per sender per round. The server records THAT
             the user got a token, but never sees the token itself.
Inputs:
    user_id (int): ID of the requesting user.
    blinded_message (int): Blinded value from blind_token.
Returns:
    int: Blind signature to return to the client.
Raises:
    PermissionError: Invalid user, wrong role, or token already issued
                     this round.
    ValueError: Malformed blinded message.
'''
def issue_blind_signature(user_id, blinded_message):

    # verify the requester exists and is a Sender
    user = get_user(user_id)
    if user is None:
        raise PermissionError("Invalid user.")
    require_permission(user["role"], "send_message")

    key = _load_signing_key()
    n = key.public_key().public_numbers().n
    d = key.private_numbers().d

    # reject out-of-range values
    if not isinstance(blinded_message, int) or not (1 < blinded_message < n):
        raise ValueError("Malformed blinded message.")

    round_id = get_current_round()

    with get_connection() as conn:

        # record issuance. The primary key enforces one per round
        try:
            conn.execute(
                """
                INSERT INTO token_issuance (user_id, round_id)
                VALUES (?, ?)
                """,
                (user_id, round_id)
            )
        except sqlite3.IntegrityError:
            raise PermissionError(
                f"Token already issued this round (round {round_id})."
            )

        log_event(conn, "token_issued", "sender", f"round={round_id}")

    # sign the blinded value: blinded^d mod n
    return pow(blinded_message, d, n)


'''
Function: verify_token
Description: Checks a token's signature and that it belongs to the
             current round. Does NOT check whether it has been spent.
Inputs:
    token (dict): Token {round_id, serial, signature}.
Returns:
    bool: True if the signature is valid for the current round.
'''
def verify_token(token):

    try:
        round_id = int(token["round_id"])
        serial = str(token["serial"])
        signature = int(token["signature"])
    except (KeyError, TypeError, ValueError):
        return False

    # expired rounds are rejected
    if round_id != get_current_round():
        return False

    n, e = get_public_key_numbers()
    if not (0 < signature < n):
        return False

    # valid if signature^e == H(token) mod n
    return pow(signature, e, n) == _hash_to_int(round_id, serial, n)


'''
Function: redeem_token
Description: Spends a token. Called when an anonymous message is sent.
             Takes NO user ID: holding a valid token is the authorization,
             and this keeps the sender anonymous at send time.
Inputs:
    token (dict): Token {round_id, serial, signature}.
Returns:
    str: token_id of the spent token (to attach to the message).
Raises:
    PermissionError: Invalid, expired, already spent, or frozen token.
'''
def redeem_token(token):

    if not verify_token(token):
        with get_connection() as conn:
            log_event(conn, "token_rejected", "sender", "invalid_or_expired")
        raise PermissionError("Invalid or expired token.")

    token_id = compute_token_id(token)

    with get_connection() as conn:

        # the primary key on token_id prevents double-spending
        try:
            conn.execute(
                """
                INSERT INTO tokens (token_id, round_id)
                VALUES (?, ?)
                """,
                (token_id, token["round_id"])
            )
        except sqlite3.IntegrityError:
            log_event(conn, "token_rejected", "sender", "already_spent")
            raise PermissionError("Token has already been used.")

        log_event(
            conn, "token_redeemed", "sender",
            f"round={token['round_id']}"
        )

    return token_id


'''
Function: freeze_token
Description: Marks a token as frozen after abuse. Only moderators can
             freeze tokens.
Inputs:
    moderator_id (int): ID of the moderator.
    token_id (str): ID of the token to freeze.
Returns:
    bool: True if frozen, False if the token does not exist.
'''
def freeze_token(moderator_id, token_id):

    # verify moderator permissions
    moderator = get_user(moderator_id)
    if moderator is None:
        raise PermissionError("Invalid moderator.")
    require_permission(moderator["role"], "freeze_token")

    with get_connection() as conn:
        cursor = conn.execute(
            "UPDATE tokens SET is_frozen = 1 WHERE token_id = ?",
            (token_id,)
        )

        frozen = cursor.rowcount > 0
        if frozen:
            log_event(conn, "token_frozen", "moderator", f"token={token_id[:12]}")

    return frozen


'''
Function: is_token_frozen
Description: Checks whether a token has been frozen by a moderator.
Inputs:
    token_id (str): ID of the token.
Returns:
    bool: True if frozen, False otherwise.
'''
def is_token_frozen(token_id):

    with get_connection() as conn:
        row = conn.execute(
            "SELECT is_frozen FROM tokens WHERE token_id = ?",
            (token_id,)
        ).fetchone()

    return bool(row and row["is_frozen"])


'''
Function: request_token
Description: Convenience wrapper that runs the full client/server flow
             (blind, sign, unblind) in one call. In a deployed system
             the blind/unblind steps would run on the sender's device.
Inputs:
    user_id (int): ID of the requesting Sender.
Returns:
    dict: Finished token {round_id, serial, signature}.
'''
def request_token(user_id):
    round_id = get_current_round()
    blinded, state = blind_token(round_id)
    blind_sig = issue_blind_signature(user_id, blinded)
    return unblind_signature(blind_sig, state)