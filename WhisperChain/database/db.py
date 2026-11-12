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


if __name__ == "__main__":
    initialize_database()
    print("Database initialized successfully")

