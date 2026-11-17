########## imports ##########
import sqlite3
from pathlib import Path


# define file paths
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "data" / "whisperchain.db"
SCHEMA_PATH = BASE_DIR / "database" / "schema.sql"

'''create a connection to the SQLite database'''
def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    return conn

'''initialize the database using schema.sql'''
def initialize_database():

    with get_connection() as conn:
        with open(SCHEMA_PATH, "r") as file:
            schema = file.read()

        conn.executescript(schema)

        # add login columns to a users table created before passwords existed
        _add_missing_user_columns(conn)


'''
add columns that were introduced after a database was first created
(CREATE TABLE IF NOT EXISTS never changes an existing table)
'''
def _add_missing_user_columns(conn):

    existing = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}

    new_columns = {
        "password_hash": "TEXT",
        "must_change_password": "INTEGER NOT NULL DEFAULT 0",
    }

    for name, definition in new_columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE users ADD COLUMN {name} {definition}")


if __name__ == "__main__":
    initialize_database()
    print("Database initialized successfully")