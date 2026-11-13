-- track user, ID, role, and public key
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (
        role IN ('sender', 'recipient', 'moderator', 'admin')
    ),
    public_key TEXT
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
CREATE TABLE IF NOT EXISTS tokens (
    token_id TEXT PRIMARY KEY,
    round_id INTEGER NOT NULL,

    used INTEGER NOT NULL DEFAULT 0
        CHECK (used IN (0, 1)),

    frozen INTEGER NOT NULL DEFAULT 0
        CHECK (frozen IN (0, 1))
);


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

