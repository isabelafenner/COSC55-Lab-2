########## imports ##########
import secrets

from database.db import initialize_database, get_connection
from core.users import register_user
from core.rounds import advance_round
from core.tokens import issue_token, freeze_token
from core.keys import setup_user_keys, load_user_private_key
from core.messages import send_message, get_message
from core.client import flag_message
from core.crypto import recover_message_key
from core.moderation import (
    submit_flag,
    get_flag_queue,
    review_flag,
    get_alerts,
    FLAG_VOLUME_THRESHOLD,
    TOKEN_REJECTION_THRESHOLD
)
from core.audit import get_audit_log, verify_audit_log


# --------------------------------------------------
# DATABASE SETUP
# --------------------------------------------------

initialize_database()

suffix = secrets.token_hex(4)

# Create test administrator
with get_connection() as conn:
    cursor = conn.execute(
        """
        INSERT INTO users (username, role)
        VALUES (?, ?)
        """,
        (f"test_admin_{suffix}", "admin")
    )

    admin_id = cursor.lastrowid

senders = [
    register_user(admin_id, f"test_sender{i}_{suffix}", "sender")
    for i in range(4)
]
recipient_id = register_user(admin_id, f"test_recipient_{suffix}", "recipient")
recipient2_id = register_user(admin_id, f"test_recipient2_{suffix}", "recipient")
moderator_id = register_user(admin_id, f"test_moderator_{suffix}", "moderator")

setup_user_keys(recipient_id)
setup_user_keys(recipient2_id)

# Fresh round so alert counts start from zero
round_id = advance_round(admin_id)

# Each sender sends one message
texts = [
    f"You are the worst TA ever ({suffix})",
    f"Nobody likes your questions ({suffix})",
    f"Stop talking in section ({suffix})",
    f"Great job on the midterm review! ({suffix})",
]
targets = [recipient_id, recipient_id, recipient_id, recipient2_id]

message_ids = []

for sender_id, recipient, text in zip(senders, targets, texts):
    token = issue_token(sender_id, round_id)
    message_ids.append(send_message(token, recipient, text))


# --------------------------------------------------
# TEST 1: RECIPIENT FLAGS A MESSAGE
# --------------------------------------------------

print("\nTest 1: Recipient flags a message")

flag1_id = flag_message(recipient_id, message_ids[0], "Harassment")

queue = get_flag_queue(moderator_id)
entry = next(f for f in queue if f["flag_id"] == flag1_id)

print("Moderator sees:", {k: entry[k] for k in ("flag_id", "content", "reason", "status")})

assert entry["content"] == texts[0]
assert not any("sender" in key for key in entry.keys())
assert "revealed_key" not in entry

print("PASS: Moderator can read the flagged message, with no sender info")


# --------------------------------------------------
# TEST 2: REPORTED CONTENT CAN'T BE FAKED
# --------------------------------------------------

print("\nTest 2: Reported content can't be faked")

# try to flag message 2 using message 1's key
wrong_key = recover_message_key(
    get_message(recipient_id, message_ids[0]),
    load_user_private_key(recipient_id)
)

try:
    submit_flag(recipient_id, message_ids[1], wrong_key, "fabricated")
    print("FAIL: Flag accepted with a key from a different message")
except ValueError:
    print("PASS: Key must match the stored message")

try:
    submit_flag(recipient_id, message_ids[1], "not-a-real-key", "fabricated")
    print("FAIL: Flag accepted with a bogus key")
except ValueError:
    print("PASS: Bogus key rejected")


# --------------------------------------------------
# TEST 3: FLAGGING RULES
# --------------------------------------------------

print("\nTest 3: Flagging rules")

try:
    flag_message(recipient2_id, message_ids[0])
    print("FAIL: Recipient flagged someone else's message")
except ValueError:
    print("PASS: Cannot flag another recipient's message")

try:
    flag_message(recipient_id, message_ids[0])
    print("FAIL: Message flagged twice")
except ValueError:
    print("PASS: Message cannot be flagged twice")

for user_id, role in [(admin_id, "admin"), (senders[0], "sender"),
                      (moderator_id, "moderator")]:
    try:
        submit_flag(user_id, message_ids[1], wrong_key)
        print(f"FAIL: {role} flagged a message")
    except PermissionError:
        print(f"PASS: {role} cannot flag messages")


# --------------------------------------------------
# TEST 4: ONLY MODERATORS SEE THE QUEUE
# --------------------------------------------------

print("\nTest 4: Flag queue access")

for user_id, role in [(admin_id, "admin"), (recipient_id, "recipient"),
                      (senders[0], "sender")]:
    try:
        get_flag_queue(user_id)
        print(f"FAIL: {role} viewed the flag queue")
    except PermissionError:
        print(f"PASS: {role} cannot view the flag queue")


# --------------------------------------------------
# TEST 5: MODERATOR REVIEW
# --------------------------------------------------

print("\nTest 5: Moderator review")

assert review_flag(moderator_id, flag1_id, "upheld") is True

pending_ids = [f["flag_id"] for f in get_flag_queue(moderator_id)]
upheld_ids = [f["flag_id"] for f in get_flag_queue(moderator_id, "upheld")]

assert flag1_id not in pending_ids
assert flag1_id in upheld_ids

print("PASS: Upheld flag moved out of the pending queue")

# freeze the token behind the upheld flag
assert freeze_token(moderator_id, entry["token_id"]) is True

print("PASS: Moderator froze the token behind the upheld flag")

try:
    review_flag(moderator_id, flag1_id, "dismissed")
    print("FAIL: Flag reviewed twice")
except ValueError:
    print("PASS: Flag cannot be reviewed twice")

flag2_id = flag_message(recipient_id, message_ids[1], "Rude")

try:
    review_flag(moderator_id, flag2_id, "delete_user")
    print("FAIL: Invalid decision accepted")
except ValueError:
    print("PASS: Invalid decision rejected")

review_flag(moderator_id, flag2_id, "dismissed")

print("PASS: Flag dismissed")


# --------------------------------------------------
# TEST 6: FLAG VOLUME ALERT
# --------------------------------------------------

print("\nTest 6: Flag volume alert")

# third flag this round reaches the threshold
flag_message(recipient_id, message_ids[2], "Mean")

round_alerts = [a for a in get_alerts(moderator_id)
                if a["round_id"] == round_id and a["rule"] == "flag_volume"]

assert FLAG_VOLUME_THRESHOLD == 3
assert len(round_alerts) == 1

print("Alert:", round_alerts[0])
print("PASS: Alert raised after", FLAG_VOLUME_THRESHOLD, "flags in one round")

# another flag in the same round shouldn't create a duplicate alert
flag_message(recipient2_id, message_ids[3], "Testing duplicates")

round_alerts = [a for a in get_alerts(moderator_id)
                if a["round_id"] == round_id and a["rule"] == "flag_volume"]

assert len(round_alerts) == 1

print("PASS: No duplicate alert for the same round")


# --------------------------------------------------
# TEST 7: TOKEN REJECTION ALERT
# --------------------------------------------------

print("\nTest 7: Token rejection alert")

for _ in range(TOKEN_REJECTION_THRESHOLD):
    try:
        send_message(secrets.token_urlsafe(32), recipient_id, "forged token")
    except ValueError:
        pass

rejection_alerts = [a for a in get_alerts(moderator_id)
                    if a["round_id"] == round_id and a["rule"] == "token_rejections"]

assert len(rejection_alerts) == 1

print("Alert:", rejection_alerts[0])
print("PASS: Alert raised after", TOKEN_REJECTION_THRESHOLD, "forged token attempts")

try:
    get_alerts(admin_id)
    print("FAIL: Admin viewed alerts")
except PermissionError:
    print("PASS: Admin cannot view alerts")


# --------------------------------------------------
# TEST 8: MODERATION EVENTS ARE LOGGED
# --------------------------------------------------

print("\nTest 8: Moderation events in the audit log")

actions = {e["action"] for e in get_audit_log(moderator_id, limit=100)}

for expected in ["message_flagged", "flag_upheld", "flag_dismissed",
                 "token_frozen", "alert_raised", "token_rejected"]:
    if expected in actions:
        print(f"PASS: {expected} logged")
    else:
        print(f"FAIL: {expected} missing from log")

with get_connection() as conn:
    full_log = " ".join(str(tuple(r)) for r in conn.execute("SELECT * FROM audit_log"))

if any(text in full_log for text in texts):
    print("FAIL: Message content in audit log")
else:
    print("PASS: No message content in audit log")


# --------------------------------------------------
# TEST 9: TAMPER DETECTION
# --------------------------------------------------

print("\nTest 9: Audit log tamper detection")

result = verify_audit_log(moderator_id)
print("Before tampering:", result)
assert result["valid"] is True

print("PASS: Audit log chain is intact")

# simulate an attacker with direct database access:
# remove the append-only triggers, then edit one entry
with get_connection() as conn:
    target = conn.execute(
        "SELECT log_id, details FROM audit_log WHERE action = 'flag_upheld' "
        "ORDER BY log_id DESC LIMIT 1"
    ).fetchone()

    conn.execute("DROP TRIGGER audit_log_no_update")
    conn.execute("DROP TRIGGER audit_log_no_delete")
    conn.execute(
        "UPDATE audit_log SET details = 'flag=covered_up' WHERE log_id = ?",
        (target["log_id"],)
    )

result = verify_audit_log(moderator_id)
print("After editing an entry:", result)

if not result["valid"] and result["first_invalid_log_id"] == target["log_id"]:
    print("PASS: Edited entry detected")
else:
    print("FAIL: Edited entry not detected")

# undo the edit, then try deleting the entry instead
with get_connection() as conn:
    conn.execute(
        "UPDATE audit_log SET details = ? WHERE log_id = ?",
        (target["details"], target["log_id"])
    )
    deleted = dict(conn.execute(
        "SELECT * FROM audit_log WHERE log_id = ?", (target["log_id"],)
    ).fetchone())
    conn.execute("DELETE FROM audit_log WHERE log_id = ?", (target["log_id"],))

result = verify_audit_log(moderator_id)
print("After deleting an entry:", result)

if not result["valid"]:
    print("PASS: Deleted entry detected")
else:
    print("FAIL: Deleted entry not detected")

# restore the entry and the triggers so later runs start clean
with get_connection() as conn:
    columns = ", ".join(deleted.keys())
    placeholders = ", ".join("?" for _ in deleted)
    conn.execute(
        f"INSERT INTO audit_log ({columns}) VALUES ({placeholders})",
        tuple(deleted.values())
    )

initialize_database()

assert verify_audit_log(moderator_id)["valid"] is True

print("PASS: Log restored and chain valid again")