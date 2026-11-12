CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (
        role IN ('sender', 'recipient', 'moderator', 'admin')
    ),
    public_key TEXT
);