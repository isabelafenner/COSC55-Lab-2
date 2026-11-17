# WhisperChain+

**Anonymous Messaging with Role-Based Control and Accountability**

WhisperChain+ is a Python-based anonymous messaging system that allows users to send encrypted messages while enforcing role-based access control (RBAC), moderation, and audit logging.

## Features

- **Role-Based Access Control:** Four roles (Admin, Sender, Recipient, and Moderator) with distinct permissions
- **Anonymous Tokens:** Senders receive one randomly generated, single-use token per messaging round
- **End-to-End Encryption:** Messages are encrypted using the recipient's public key and decrypted using their private key
- **Round Management:** Administrators can advance messaging rounds, invalidating tokens from previous rounds
- **Moderation:** Recipients can flag inappropriate messages, and Moderators can review flagged content and freeze tokens
- **Audit Logging:** Records system activity to support accountability without directly identifying message senders
- **Command-Line Interface:** Interactive CLI for accessing the system's functionality

## Project Structure

```text
WhisperChain/
├── core/
│   ├── audit.py
│   ├── client.py
│   ├── crypto.py
│   ├── keys.py
│   ├── messages.py
│   ├── moderation.py
│   ├── rbac.py
│   ├── rounds.py
│   ├── tokens.py
│   └── users.py
├── data/
├── database/
│   ├── db.py
│   └── schema.sql
├── main.py
├── test_admin.py
├── test_audit.py
├── test_crypto.py
├── test_full_rbac.py
├── test_messages.py
├── test_moderation.py
├── test_rbac.py
├── test_rounds.py
├── test_tokens.py
└── test_users.py
README.md
```

## Setup and Usage

**1. Install dependencies**

```bash
pip install cryptography
```

**2. Initialize the SQLite database**

From the project root:

```bash
python -m database.db
```

**3. Launch the application**

```bash
python main.py
```

Follow the interactive CLI prompts to access the system's functionality.

## Technologies

- **Python** - Application logic and command-line interface
- **SQLite** - User, token, message, and audit data storage
- **Cryptography** - Public-key and symmetric message encryption

## Security Considerations

WhisperChain+ separates sender identities from message records, uses single-use tokens, and enforces role-based permissions. Registered accounts receive a default password originally and then have the option to update that password.

