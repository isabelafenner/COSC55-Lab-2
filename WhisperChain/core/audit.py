'''
Function: log_event
Description: Appends a role-level event to the audit log.
             Never pass usernames or user IDs in details.
Inputs:
    conn (sqlite3.Connection): Open connection (keeps the log entry in
                               the same transaction as the action).
    action (str): Event type, e.g. "token_issued".
    role (str): Role involved in the event.
    details (str): Optional non-identifying context.
'''
def log_event(conn, action, role, details=None):
    conn.execute(
        """
        INSERT INTO audit_log (action, role, details)
        VALUES (?, ?, ?)
        """,
        (action, role, details)
    )