
from core.crypto import (
    generate_key_pair,
    encrypt_message,
    decrypt_message
)


# --------------------------------------------------
# TEST 1: KEY GENERATION
# --------------------------------------------------

print("\nTest 1: Key generation")

public_key, private_key = generate_key_pair()

assert "BEGIN PUBLIC KEY" in public_key
assert "BEGIN PRIVATE KEY" in private_key

print("PASS: Public/private key pair generated")


# --------------------------------------------------
# TEST 2: MESSAGE ENCRYPTION
# --------------------------------------------------

print("\nTest 2: Message encryption")

message = "Hello, this is a secret message!"

ciphertext = encrypt_message(message, public_key)

assert message not in ciphertext

print("PASS: Message encrypted successfully")


# --------------------------------------------------
# TEST 3: MESSAGE DECRYPTION
# --------------------------------------------------

print("\nTest 3: Message decryption")

decrypted_message = decrypt_message(
    ciphertext,
    private_key
)

assert decrypted_message == message

print("PASS: Original message recovered")


# --------------------------------------------------
# TEST 4: INCORRECT PRIVATE KEY
# --------------------------------------------------

print("\nTest 4: Incorrect private key")

other_public_key, other_private_key = generate_key_pair()

try:
    decrypt_message(ciphertext, other_private_key)
    print("FAIL: Incorrect private key decrypted message")

except ValueError:
    print("PASS: Incorrect private key rejected")

