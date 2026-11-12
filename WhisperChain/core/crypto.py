########## imports ##########
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


'''
OVERVIEW: Hybrid end-to-end encryption (RSA-OAEP + AES-256-GCM)

    RSA can only encrypt ~190 bytes directly, so each message is encrypted
    in two layers:
        1. A fresh random AES-256 key encrypts the message (AES-GCM).
           GCM also authenticates it, so tampering is detected.
        2. The recipient's RSA public key encrypts ("wraps") that AES key.
    Only the holder of the recipient's private key can unwrap the AES key
    and read the message.

    Ciphertext layout:
        [2 bytes: wrapped key length][wrapped AES key][12-byte nonce][AES-GCM output]
'''


RSA_KEY_SIZE = 2048
NONCE_SIZE = 12

OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
)


# =====================================================================
# Key generation and serialization
# =====================================================================

'''
Function: generate_keypair
Description: Generates a new RSA key pair for a user.
Returns:
    tuple: (private_pem, public_pem) as bytes.
'''
def generate_keypair():

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem


'''
Function: load_public_key
Description: Parses a PEM public key and checks it is a usable RSA key.
Inputs:
    public_pem (bytes or str): PEM-encoded public key.
Returns:
    RSAPublicKey: The parsed key.
Raises:
    ValueError: If the key is malformed, not RSA, or too small.
'''
def load_public_key(public_pem):

    if isinstance(public_pem, str):
        public_pem = public_pem.encode()

    key = serialization.load_pem_public_key(public_pem)

    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < RSA_KEY_SIZE:
        raise ValueError(f"Public key must be RSA with at least {RSA_KEY_SIZE} bits.")

    return key


'''
Function: load_private_key
Description: Parses a PEM private key.
Inputs:
    private_pem (bytes): PEM-encoded private key.
Returns:
    RSAPrivateKey: The parsed key.
'''
def load_private_key(private_pem):
    return serialization.load_pem_private_key(private_pem, password=None)


# =====================================================================
# Encryption and decryption
# =====================================================================

'''
Function: encrypt_message
Description: Encrypts a message for a recipient using their public key.
Inputs:
    public_pem (bytes or str): Recipient's PEM public key.
    plaintext (str): Message to encrypt.
    associated_data (bytes): Context bound to the ciphertext (not secret,
                             but decryption fails if it changes).
Returns:
    bytes: Packed ciphertext.
'''
def encrypt_message(public_pem, plaintext, associated_data):

    public_key = load_public_key(public_pem)

    # layer 1: encrypt the message with a fresh AES key
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(NONCE_SIZE)
    encrypted_body = AESGCM(aes_key).encrypt(
        nonce, plaintext.encode("utf-8"), associated_data
    )

    # layer 2: wrap the AES key with the recipient's RSA public key
    wrapped_key = public_key.encrypt(aes_key, OAEP)

    return struct.pack(">H", len(wrapped_key)) + wrapped_key + nonce + encrypted_body


'''
Function: decrypt_message
Description: Decrypts a message with the recipient's private key.
Inputs:
    private_key (RSAPrivateKey): Recipient's private key.
    ciphertext (bytes): Packed ciphertext from encrypt_message.
    associated_data (bytes): Must match what was used at encryption.
Returns:
    str: The plaintext message.
Raises:
    ValueError: If the key is wrong or the ciphertext was tampered with.
'''
def decrypt_message(private_key, ciphertext, associated_data):

    try:
        # unpack the pieces
        (key_len,) = struct.unpack(">H", ciphertext[:2])
        wrapped_key = ciphertext[2:2 + key_len]
        nonce = ciphertext[2 + key_len:2 + key_len + NONCE_SIZE]
        encrypted_body = ciphertext[2 + key_len + NONCE_SIZE:]

        # unwrap the AES key, then decrypt and verify the message
        aes_key = private_key.decrypt(wrapped_key, OAEP)
        plaintext = AESGCM(aes_key).decrypt(nonce, encrypted_body, associated_data)

    except Exception:
        # one generic error, so failures don't reveal which step broke
        raise ValueError("Decryption failed: wrong key or tampered message.")

    return plaintext.decode("utf-8")