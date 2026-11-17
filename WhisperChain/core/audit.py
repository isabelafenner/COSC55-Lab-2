########## imports ##########
import hashlib
import hmac
import secrets
from datetime import datetime, timezone

from database.db import get_connection, BASE_DIR


'''
OVERVIEW: Tamper-evident audit log (HMAC hash chain)

    Every entry stores:
        prev_hash  = the previous entry's hash
        entry_hash = HMAC(audit key, prev_hash | timestamp | action | role | details)

    Editing any entry changes its hash, so it no longer matches the
    prev_hash stored in the next entry. Deleting an entry breaks the link
    between its neighbours. verify_audit_log() walks the chain and reports
    the first entry that doesn't check out.

    Using an HMAC (a keyed hash) instead of a plain hash means someone with
    the database file but not the audit key can't rebuild a fake chain.
    The key lives in data/audit_hmac.key, separate from the database.

    Database triggers also block UPDATE and DELETE, so entries can't be
    changed through normal code paths. The chain catches changes that
    bypass the triggers.
'''


AUDIT_KEY_PATH = BASE_DIR / "data" / "audit_hmac.key"
GENESIS_HASH = "0" * 64


'''
Function: _load_audit_key
Description: Loads the audit log's HMAC key, generating it on first use.
Returns:
    bytes: 32-byte secret key.
'''
def _load_audit_key():

    if not AUDIT_KEY_PATH.exists():
        AUDIT_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        AUDIT_KEY_PATH.write_bytes(secrets.token_bytes(32))
        AUDIT_KEY_PATH.chmod(0o600)

    return AUDIT_KEY_PATH.read_bytes()


'''
Function: _compute_hash
Description: Computes an entry's HMAC from its contents and the previous hash.
Returns:
    str: Hex digest.
'''
def _compute_hash(prev_hash, timestamp, action, role, details):

    data = "|".join([
        prev_hash,
        timestamp,
        action,
        role,
        "" if details is None else str(details)
    ]).encode("utf-8")

    return hmac.new(_load_audit_key(), data, hashlib.sha256).hexdigest()


'''
Function: log_event
Description: Appends a role-level event to the audit log and links it to
             the previous entry. Never pass usernames or user IDs in details.
Inputs:
    conn (sqlite3.Connection): Open connection (keeps the log entry in
                               the same transaction as the action).
    action (str): Event type, e.g. "token_issued".
    role (str): Role involved in the event.
    details (str): Optional non-identifying context.
'''
def log_event(conn, action, role, details=None):

    # hash of the most recent entry, or the genesis value if the log is empty
    last = conn.execute(
        "SELECT entry_hash FROM audit_log ORDER BY log_id DESC LIMIT 1"
    ).fetchone()

    prev_hash = last["entry_hash"] if last else GENESIS_HASH

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    entry_hash = _compute_hash(prev_hash, timestamp, action, role, details)

    conn.execute(
        """
        INSERT INTO audit_log
            (timestamp, action, role, details, prev_hash, entry_hash)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (timestamp, action, role, details, prev_hash, entry_hash)
    )


'''
Function: _require_moderator
Description: Verifies the user exists and can view audit logs.
'''
def _require_moderator(moderator_id):

    # imported here to avoid a circular import (users.py imports audit.py)
    from core.users import get_user
    from core.rbac import require_permission

    moderator = get_user(moderator_id)

    if moderator is None:
        raise ValueError("User does not exist.")

    require_permission(moderator["role"], "view_audit_logs")


'''
Function: get_audit_log
Description: Retrieves audit log entries. Only Moderators can view
             the audit log.
Inputs:
    moderator_id (int): ID of the Moderator.
    limit (int): Maximum number of entries to return (newest first).
Returns:
    list: Dicts with log_id, timestamp, action, role, details.
'''
def get_audit_log(moderator_id, limit=50):

    _require_moderator(moderator_id)

    with get_connection() as conn:
        entries = conn.execute(
            """
            SELECT log_id, timestamp, action, role, details
            FROM audit_log
            ORDER BY log_id DESC
            LIMIT ?
            """,
            (limit,)
        ).fetchall()

    return [dict(entry) for entry in entries]


'''
Function: verify_audit_log
Description: Walks the hash chain from the first entry to the last and
             checks every link. Only Moderators can run verification.
Inputs:
    moderator_id (int): ID of the Moderator.
Returns:
    dict: {
        "valid": True if every entry checks out,
        "entries_checked": number of entries examined,
        "first_invalid_log_id": log_id of the first broken entry, or None
    }
'''
def verify_audit_log(moderator_id):

    _require_moderator(moderator_id)

    with get_connection() as conn:
        entries = conn.execute(
            "SELECT * FROM audit_log ORDER BY log_id"
        ).fetchall()

    expected_prev = GENESIS_HASH

    for entry in entries:

        recomputed = _compute_hash(
            entry["prev_hash"],
            entry["timestamp"],
            entry["action"],
            entry["role"],
            entry["details"]
        )

        # broken link (entry removed or reordered) or altered contents
        if entry["prev_hash"] != expected_prev or entry["entry_hash"] != recomputed:
            return {
                "valid": False,
                "entries_checked": len(entries),
                "first_invalid_log_id": entry["log_id"]
            }

        expected_prev = entry["entry_hash"]

    return {
        "valid": True,
        "entries_checked": len(entries),
        "first_invalid_log_id": None
    }