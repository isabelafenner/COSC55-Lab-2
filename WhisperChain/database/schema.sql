-- track user, ID, role, public key, and login credentials
--   password_hash:        scrypt hash with its own salt (never plaintext)
--   must_change_password: 1 while the user still has the default password
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (
        role IN ('sender', 'recipient', 'moderator', 'admin')
    ),
    public_key TEXT,
    password_hash TEXT,
    must_change_password INTEGER NOT NULL DEFAULT 0
);


-- track token issuance for each sender and round
CREATE TABLE IF NOT EXISTS token_issuance (
    user_id INTEGER NOT NULL,
    round_id INTEGER NOT NULL,

    PRIMARY KEY (user_id, round_id),

    FOREIGN KEY (user_id)
        REFERENCES users(user_id)
);


-- store anonymous messaging tokens
-- WITHOUT ROWID: rows are stored by the random token_id instead of
-- insertion order, so they can't be lined up with token_issuance rows
CREATE TABLE IF NOT EXISTS tokens (
    token_id TEXT PRIMARY KEY,
    round_id INTEGER NOT NULL,

    used INTEGER NOT NULL DEFAULT 0
        CHECK (used IN (0, 1)),

    frozen INTEGER NOT NULL DEFAULT 0
        CHECK (frozen IN (0, 1))
) WITHOUT ROWID;


-- stores encrypted messages without identifying Senders
CREATE TABLE IF NOT EXISTS messages (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,

    recipient_id INTEGER NOT NULL,
    token_id TEXT NOT NULL UNIQUE,
    round_id INTEGER NOT NULL,

    ciphertext TEXT NOT NULL,

    FOREIGN KEY (recipient_id)
        REFERENCES users(user_id),

    FOREIGN KEY (token_id)
        REFERENCES tokens(token_id)
);


-- stores the current active messaging round
CREATE TABLE IF NOT EXISTS system_state (
    state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
    current_round INTEGER NOT NULL DEFAULT 1
        CHECK (current_round > 0)
);


-- initialize the active round to 1
-- only insert if the record does not already exist
INSERT OR IGNORE INTO system_state (
    state_id,
    current_round
)
VALUES (1, 1);

-- append-only audit log: role-level metadata only, never identities
-- each entry stores the previous entry's hash, so editing or removing
-- any entry breaks the chain (see core/audit.py: verify_audit_log)
CREATE TABLE IF NOT EXISTS audit_log (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    role TEXT NOT NULL,
    details TEXT,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL
);


-- block edits and deletes so the log can only grow
CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only');
END;


-- flagged messages awaiting or after moderator review
-- revealed_key: the one-time key for THIS message only, handed over by
-- the Recipient so a Moderator can read and verify the flagged content
CREATE TABLE IF NOT EXISTS flags (
    flag_id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL UNIQUE,
    reason TEXT,
    revealed_key TEXT NOT NULL,

    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'upheld', 'dismissed')),

    flagged_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TEXT,

    FOREIGN KEY (message_id)
        REFERENCES messages(message_id)
);


-- alerts raised by automated rules (one per rule per round)
CREATE TABLE IF NOT EXISTS alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule TEXT NOT NULL,
    round_id INTEGER NOT NULL,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (rule, round_id)
);