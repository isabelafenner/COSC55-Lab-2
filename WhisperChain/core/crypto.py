########## imports ##########
import json
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


'''
Function: generate_key_pair
Description:
    Generates an RSA public/private key pair.
    The public key can be shared with Senders.
    The private key must remain secret.

Inputs:
    None

Returns:
    tuple: (public_key, private_key), both as PEM strings.
'''
def generate_key_pair():

    # generate a new RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
    )

    # derive the corresponding public key
    public_key = private_key.public_key()

    # convert the public key into a storable string
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    # convert the private key into a string
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    return public_pem, private_pem


'''
Function: encrypt_message
Description:
    Encrypts a plaintext message using hybrid encryption.
    Fernet encrypts the message, and RSA encrypts the
    Fernet key using the Recipient's public key.

Inputs:
    plaintext (str): Message to encrypt.
    public_key_pem (str): Recipient's public key.

Returns:
    str: JSON string containing the encrypted message
         and encrypted symmetric key.
'''
def encrypt_message(plaintext, public_key_pem):

    # load the Recipient's public key
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode("utf-8")
    )

    # generate a random symmetric encryption key
    symmetric_key = Fernet.generate_key()

    # encrypt the message using Fernet
    fernet = Fernet(symmetric_key)
    encrypted_message = fernet.encrypt(
        plaintext.encode("utf-8")
    )

    # encrypt the symmetric key using RSA
    encrypted_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # encode the encrypted key as text for JSON storage
    encoded_key = base64.b64encode(
        encrypted_key
    ).decode("utf-8")

    # package both encrypted values together
    ciphertext = {
        "encrypted_key": encoded_key,
        "encrypted_message": encrypted_message.decode("utf-8")
    }

    return json.dumps(ciphertext)


'''
Function: decrypt_message
Description:
    Decrypts a message using the Recipient's private key.
    RSA first decrypts the symmetric key, which Fernet
    then uses to decrypt the message.

Inputs:
    ciphertext (str): Encrypted message JSON.
    private_key_pem (str): Recipient's private key.

Returns:
    str: Original plaintext message.
'''
def decrypt_message(ciphertext, private_key_pem):

    # load the Recipient's private key
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None
    )

    # extract the encrypted message and symmetric key
    encrypted_data = json.loads(ciphertext)

    encrypted_key = base64.b64decode(
        encrypted_data["encrypted_key"]
    )

    encrypted_message = encrypted_data[
        "encrypted_message"
    ].encode("utf-8")

    # decrypt the symmetric key using RSA
    symmetric_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # decrypt the message using Fernet
    fernet = Fernet(symmetric_key)

    plaintext = fernet.decrypt(
        encrypted_message
    )

    return plaintext.decode("utf-8")


'''
Function: recover_message_key
Description:
    Recovers the one-time Fernet key of a single message using the
    Recipient's private key. Used when flagging: revealing this key
    exposes only this one message, never the private key itself.

Inputs:
    ciphertext (str): Encrypted message JSON.
    private_key_pem (str): Recipient's private key.

Returns:
    str: The message's Fernet key.
'''
def recover_message_key(ciphertext, private_key_pem):

    # load the Recipient's private key
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None
    )

    # unwrap the encrypted symmetric key
    encrypted_key = base64.b64decode(
        json.loads(ciphertext)["encrypted_key"]
    )

    symmetric_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return symmetric_key.decode("utf-8")


'''
Function: decrypt_with_message_key
Description:
    Decrypts a message using its revealed one-time Fernet key.
    Fernet authenticates the ciphertext, so this fails if the key
    does not belong to this message or the message was altered.

Inputs:
    ciphertext (str): Encrypted message JSON.
    message_key (str): Fernet key from recover_message_key.

Returns:
    str: Original plaintext message.

Raises:
    ValueError: If the key does not match the message.
'''
def decrypt_with_message_key(ciphertext, message_key):

    try:
        encrypted_message = json.loads(ciphertext)["encrypted_message"]
        plaintext = Fernet(message_key.encode("utf-8")).decrypt(
            encrypted_message.encode("utf-8")
        )

    except Exception as error:
        raise ValueError("Key does not match this message.") from error

    return plaintext.decode("utf-8")