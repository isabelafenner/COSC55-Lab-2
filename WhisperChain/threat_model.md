# WhisperChain+ Threat Model

*Last updated: 2026-11-13*

## 1. Overview

WhisperChain+ keeps message content and sender identity hidden from everyone except the intended recipient. The main remaining risk is a compromised server process at the moment a token is issued.

Senders send one anonymous, encrypted compliment per round to a Recipient. Moderators review flagged messages, and Admins manage users, roles, keys and rounds. Every action is checked against a role-permission table and recorded in a hash-chained audit log.

**Scope.** This model covers the prototype as built: a single Python program over one SQLite database. The split between client and server is a boundary in the code, not a network. In a deployment, all client–server traffic would run over TLS.

**Trust assumptions**

- Each user's device is trusted to hold their private key.
- The server runs the code as written and does not secretly record which token it gave to whom.
- The operating system protects key files with owner-only permissions (`600`).
- The `cryptography` library's RSA-OAEP and Fernet implementations are sound.
- **Authentication is out of scope.** Functions trust the `user_id` they are given. A deployed system would put login and sessions in front of every call.

## 2. Assets and trust boundaries

| Asset | Where it lives | Who should see it |
| --- | --- | --- |
| Message content | `messages.ciphertext` (encrypted) | Recipient only; a Moderator after it is flagged |
| Sender identity behind a message | Nowhere: the `messages` and `tokens` tables have no user column | No one |
| Who received a token this round | `token_issuance` (`user_id`, `round_id`) | Server, to enforce one token per round |
| Anonymous tokens | `tokens` table, stored by random ID (`WITHOUT ROWID`) | The Sender who holds it |
| User private keys | `client_keys/user_<id>.pem` (the user's device) | That user only |
| User public keys | `users.public_key` | Anyone |
| Flag keys (one message's key each) | `flags.revealed_key` | Moderators |
| Audit log | `audit_log` table | Moderators |
| Audit HMAC key | `data/audit_hmac.key` | The server process only |

Plaintext and private keys exist only inside the device box. Everything that crosses into the server is either ciphertext, an anonymous token, or a single message's key revealed by its recipient when flagging.

## 3. Adversaries

| Adversary | Can do | Wants |
| --- | --- | --- |
| Abusive sender | Hold a valid sender account and a token each round | Harass a recipient, send more than allowed, avoid being stopped |
| Curious or malicious recipient | Read their own inbox, flag messages | Learn who sent a message, get an innocent message punished |
| Compromised admin account | Register users, change roles, reset keys, advance rounds | Read messages, unmask senders, hide their tracks |
| Compromised moderator account | See flagged content, freeze tokens, view the audit log | Read unflagged messages, unmask senders |
| Attacker with the database file | Read and edit every table directly, bypassing the code | Read messages, link tokens to senders, rewrite the log |
| Network eavesdropper | Watch traffic between clients and the server | Read messages, steal tokens in transit |

## 4. Role-permission matrix

Access control is role-based: `core/rbac.py` maps each role to a set of permissions, and every protected function calls `require_permission` before doing anything.

| Permission | Function(s) | Sender | Recipient | Moderator | Admin |
| --- | --- | :-: | :-: | :-: | :-: |
| `send_message` | `issue_token` | ✅ | | | |
| `read_messages` | `get_messages`, `get_message` | | ✅ | | |
| `flag_message` | `submit_flag` | | ✅ | | |
| `review_flags` | `get_flag_queue`, `review_flag`, `get_alerts` | | | ✅ | |
| `freeze_token` | `freeze_token` | | | ✅ | |
| `view_audit_logs` | `get_audit_log`, `verify_audit_log` | | | ✅ | |
| `register_user` | `register_user` | | | | ✅ |
| `assign_roles` | `update_user_role` | | | | ✅ |
| `manage_public_keys` | `reset_public_key` | | | | ✅ |
| `advance_round` | `advance_round` | | | | ✅ |
| `manage_policies` | *(reserved, not used yet)* | | | | ✅ |

Two actions need no role permission:

- **Sending a message.** `send_message` takes no user ID: holding a valid token is the authorization. This keeps the sender anonymous at send time.
- **Registering your own public key.** Any user can do this exactly once. After that, only an Admin can clear it.

**Separation of duties.** Admins manage accounts but cannot read messages, see flags or view the audit log. Moderators see flagged content and the log but cannot manage accounts or read unflagged messages.

## 5. Threats and defenses

| # | Threat | Defense in the code | Tested in | Residual risk |
| --- | --- | --- | --- | --- |
| T1 | A sender sends more than one message per round | `token_issuance` primary key (`user_id`, `round_id`) allows one token per sender per round; a token is marked used in the same transaction that stores the message | `test_tokens` 2, 5; `test_messages` 5 | None within the rules; see T13 for fake accounts |
| T2 | Forged or guessed tokens | Tokens are 256-bit random values (`secrets.token_urlsafe(32)`) and must exist in `tokens`; 5 failed uses in a round raise a `token_rejections` alert | `test_tokens` 4; `test_moderation` 7 | Guessing is infeasible |
| T3 | Replaying a used or old token | Single-use `used` flag, updated atomically; tokens only work in the round they were issued for | `test_tokens` 5; `test_messages` 11 | None |
| T4 | Linking a token back to its sender | No user column in `tokens` or `messages`; `tokens` is `WITHOUT ROWID`, so row order can't be matched to `token_issuance`; the audit log records roles, never users | `test_tokens` 9; `test_audit` 2 | The server knows who got which token at issuance; `token_issued` and `message_sent` timestamps could be correlated |
| T5 | The server or a DB thief reads messages | Hybrid end-to-end encryption: RSA-3072 OAEP wraps a fresh Fernet key per message; private keys stay on the device; the server returns ciphertext only and `client.py` decrypts | `test_messages` 1, 3b, 4, 7; `test_crypto` 4 | Message length is visible (no padding) |
| T6 | Swapping in an attacker's public key to read future messages | A user can register a key once; Admins can only clear a key, never set one; resets are logged | `test_messages` 2 | After a reset, nothing proves the next key belongs to the real user (no authentication, no fingerprint check) |
| T7 | An Admin reads messages or flags | Admin role lacks `read_messages`, `review_flags` and `view_audit_logs` | `test_messages` 8; `test_moderation` 4 | See T13 (admin creates a moderator account) |
| T8 | A Moderator reads unflagged messages | Moderator role lacks `read_messages`; the flag queue only contains messages whose recipient revealed the key | `test_messages` 8; `test_moderation` 1 | Moderators can read every flagged message |
| T9 | A recipient fakes a report | Flagging reveals the message's own key; the server checks it decrypts the stored ciphertext (Fernet is authenticated), so made-up content is rejected; one flag per message; own inbox only | `test_moderation` 2, 3 | A recipient can still flag a harmless message; the Moderator decides |
| T10 | Tampering with stored messages | Fernet's HMAC rejects any change to the encrypted body | `test_messages` 9 | Ciphertext isn't bound to its recipient or token, so a DB attacker could swap `token_id` values between messages and get the wrong token frozen |
| T11 | Editing or deleting audit log entries | Database triggers block `UPDATE` and `DELETE`; each entry carries an HMAC of the previous entry, and `verify_audit_log` finds the first broken link | `test_audit` 4, 5; `test_moderation` 9 | Deleting the newest entries isn't detected; an attacker with both the DB and `audit_hmac.key` can rebuild the chain |
| T12 | Network eavesdropping | Message content is encrypted before it leaves the device | — | Tokens and flag keys travel in plaintext without TLS; the prototype has no network layer yet |
| T13 | Privilege abuse via accounts | Role values are limited by a `CHECK` constraint; only Admins register users or change roles; every change is logged | `test_admin` 2, 4 | An Admin can create fake sender accounts (more tokens) or a moderator account they control |
| T14 | Stolen private key file | File permissions `600` | — | Keys are stored without a passphrase |

## 6. The spec's three questions

### What happens if the admin is compromised?

**What the attacker gets:**

- They can create sock-puppet sender accounts. Each one gets a token per round, which gets around the one-message limit.
- They can create a moderator account they control, and through it read flagged messages.
- They can reset a user's public key. Since the prototype has no authentication, they could then register their own key for that user and read that user's *future* messages.
- They can advance rounds early, which expires everyone's unused tokens (denial of service).

**What they can't do:**

- Read existing messages, because only recipients hold the private keys.
- Unmask senders, because no table stores the link between a token and a user.
- Read flags or the audit log directly.
- Edit the log without detection, unless they also hold `audit_hmac.key`.

**Detection:** every registration, role change, key reset and round change is in the audit log, and Moderators can review it. A burst of `user_registered` or `public_key_reset` entries is the signal.

**Future fixes:** require a second Admin to approve registrations and key resets, and show users their key's fingerprint so they can notice a swap.

### What if tokens are shared?

A token is a bearer credential: whoever holds it can send one message.

- **Sharing doesn't increase volume.** A sender who gives away their token gives away their own one message for that round, so the total stays at one per sender per round.
- **The recipient of the shared token is anonymous too.** Abuse is traced to the token, not a person.
- **Moderators can still act.** A flagged message's token can be frozen whoever used it.

We can't stop sharing without linking tokens to identities, which would break anonymity. We accept this trade-off. Tokens *stolen* in transit are a separate risk, covered by TLS in deployment (T12).

### How do you ensure nonrepudiation?

Nonrepudiation conflicts with anonymity, so it's applied selectively:

- **Senders can deny sending a message, by design.** The system can't prove who sent it, because that would break the core anonymity requirement.
- **Message content can't be denied or faked.** The token that sent a message is stored with it and can only be used once. When a message is flagged, the revealed key proves the reported text is exactly what was stored, so neither the sender's token nor the recipient can dispute it.
- **System actions can't be quietly undone.** The HMAC-chained audit log makes edits and deletions detectable. The log records *roles*, not individual accounts, so it shows that "an admin" acted, not which one. Per-account signing would close this gap, but it would also put identities into the log.

### What does freezing a token do, and what can't it do?

**What it does.** A Moderator who upholds a flag can freeze the token that sent the flagged message.

- Every path that accepts a token rejects a frozen one: `send_message`, `use_token` and `validate_token` all require `frozen = 0`. Tested in `test_tokens` 7, `test_messages` 10 and `test_moderation` 5.
- Usually the token has already been spent, so the single-use check already blocks it. In that case the freeze records the moderation decision (`flag_upheld` and `token_frozen` in the audit log) and marks the token permanently unusable.

**What it can't do: block the same sender in later rounds.** This is deliberate.

- Each round, a sender gets a fresh token with no link to their earlier ones.
- The server stores no token-to-user mapping. `token_issuance` records only that a user received *a* token in a round, and `tokens` has no user column.
- So a frozen token can't be traced to a person, and the sender's next-round token can't be recognized or blocked.

Blocking a sender across rounds would require linking tokens to identities, which would break the unlinkability requirement. We accept this limitation. Its impact is bounded:

- An abusive sender can still send at most one message per round.
- Every message they send can be flagged and its token frozen.
- Repeated flagging raises a `flag_volume` alert, so moderators see a pattern even without knowing who is behind it.

## 7. Residual risks and future work

| Risk | Possible fix |
| --- | --- |
| No authentication: functions trust the `user_id` they're given | Login and sessions in front of every call |
| The server knows who received which token at issuance | Blind-signature tokens, so the server signs a token it never sees |
| Timing correlation between `token_issued` and `message_sent` | Random delay before sending, or coarser log timestamps |
| Message length is visible | Pad messages to a fixed size before encrypting |
| Ciphertext isn't bound to its recipient or token | Authenticated encryption with that context as associated data (e.g. AES-GCM) |
| Private keys and `audit_hmac.key` stored without a passphrase | Passphrase encryption, or a key-management service |
| Deleting the newest log entries isn't detected | Publish or store the latest chain hash somewhere outside the database |
| Admins can create accounts they control | Two-admin approval for registrations and role changes |
| Freezing can't block a sender in later rounds | Accepted by design: future tokens stay unlinkable and no token-to-user mapping is stored (section 6) |
| No TLS in the prototype | Run the API over HTTPS in deployment |