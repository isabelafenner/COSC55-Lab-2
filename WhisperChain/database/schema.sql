CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (
        role IN ('sender', 'recipient', 'moderator', 'admin')
    ),
    public_key TEXT
);


-- ===================== PHASE 2: TOKENS =====================

-- Messaging rounds. Each sender may obtain one token per round.
CREATE TABLE IF NOT EXISTS rounds (
    round_id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1))
);

-- At most one active round at a time
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_round
    ON rounds (is_active) WHERE is_active = 1;

-- Seed the first round on a fresh database
INSERT OR IGNORE INTO rounds (round_id, is_active) VALUES (1, 1);


-- Issuance ledger: WHO received a token in WHICH round.
-- Deliberately stores NO token data, so it cannot be joined to
-- the tokens table. Its only job is enforcing one token per round.
CREATE TABLE IF NOT EXISTS token_issuance (
    user_id INTEGER NOT NULL,
    round_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, round_id),
    FOREIGN KEY (user_id) REFERENCES users (user_id),
    FOREIGN KEY (round_id) REFERENCES rounds (round_id)
);


-- Redeemed tokens: WHAT was used, never WHO used it.
-- token_id is a hash of the token, so the raw token is never stored.
CREATE TABLE IF NOT EXISTS tokens (
    token_id TEXT PRIMARY KEY,
    round_id INTEGER NOT NULL,
    redeemed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_frozen INTEGER NOT NULL DEFAULT 0 CHECK (is_frozen IN (0, 1)),
    FOREIGN KEY (round_id) REFERENCES rounds (round_id)
);


-- Append-only audit log: role-level metadata only, never identities
CREATE TABLE IF NOT EXISTS audit_log (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    action TEXT NOT NULL,
    role TEXT NOT NULL,
    details TEXT
);

-- Enforce append-only at the database level
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


-- ===================== PHASE 3: MESSAGES =====================

-- Encrypted messages. Stores NO sender identity and no plaintext.
--   recipient_id: needed to route the message to an inbox
--   token_id:     the anonymous token that paid for it (for freezing)
--   ciphertext:   RSA-wrapped AES key + nonce + AES-GCM ciphertext
--   is_flagged:   reserved for Phase 4 moderation
CREATE TABLE IF NOT EXISTS messages (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id INTEGER NOT NULL,
    round_id INTEGER NOT NULL,
    token_id TEXT NOT NULL UNIQUE,
    ciphertext BLOB NOT NULL,
    is_flagged INTEGER NOT NULL DEFAULT 0 CHECK (is_flagged IN (0, 1)),
    FOREIGN KEY (recipient_id) REFERENCES users (user_id),
    FOREIGN KEY (round_id) REFERENCES rounds (round_id),
    FOREIGN KEY (token_id) REFERENCES tokens (token_id)
);