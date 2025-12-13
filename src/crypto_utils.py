"""
crypto_utils.py


This file contains all cryptographic tools used.

It provides functions for:
- symmetric encryption and decryption of data;
- asymmetric encryption for key distribution;
- digital signatures;
- basic key serialization and storage.

Everything was implemented using standard, well-established 
algorithms provided by the cryptography library.
"""

import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


# ==============================================================
# KEY FILE MANAGEMENT
# ==============================================================

def save_key_to_file(key, filename, folder="keys"):
    """
    Saves raw key bytes to a file on disk.
    If the target folder does not exist, it is created automatically.

    - param key: Key bytes to store
    - param filename: Name of the file
    - param folder: Directory where keys are stored
    - return: Full path to the saved file
    """

    if not os.path.exists(folder):
        os.makedirs(folder)
    
    filepath = os.path.join(folder, filename)
    with open(filepath, "wb") as key_file:
        key_file.write(key)
    return filepath

def load_key_from_file(filename, folder="keys"):
    """
    Loads raw key bytes from a file on disk.
    """

    filepath = os.path.join(folder, filename)
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Key file not found: {filepath}")
    return open(filepath, "rb").read()


# ==============================================================
# SYMMETRIC CRYPTOGRAPHY (AES-128 + HMAC)
# Slide 56: Authenticated Encryption (Encrypt-then-MAC)
# ==============================================================
# Uses Fernet --> AES encryption with built-in authentication

def generate_symmetric_key():
    """
    Generates a new symmetric key using Fernet (AES + HMAC).
    """

    return Fernet.generate_key()

def encrypt_data(key, plaintext):
    """
    Encrypts plaintext data using a symmetric key with Fernet (AES).
    """

    f = Fernet(key)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    return f.encrypt(plaintext)

def decrypt_data(key, ciphertext):
    """
    Decrypts data using a symmetric key and verifies its integrity.
    """

    f = Fernet(key)
    return f.decrypt(ciphertext).decode('utf-8')


# ==============================================================
# ASYMMETRIC CRYPTOGRAPHY (RSA-PSS)
# Slide 62: Digital Signatures & Public Key Encryption
# ==============================================================
# Used for key exchange and digital signatures

def generate_key_pair():
    """
    Generates a new RSA 2048-bit key pair.

    The private key is used for decryption and signing, while the public key
    is shared with other peers.
    """

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """
    Converts the public key to PEM format for network transmission.
    """

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

def load_public_key(pem_string):
    """
    Loads a public key from a PEM-encoded string.
    """

    return serialization.load_pem_public_key(pem_string.encode('utf-8'))

def sign_data(private_key, data):
    """
    Signs data using the sender's private RSA-PSS with SHA256 key.
    This signature allows receivers to verify both integrity and authenticity.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
        
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(public_key_pem, data, signature_b64):
    """
    Verifies a digital signature using the sender's public key.
    """

    try:
        public_key = load_public_key(public_key_pem)
        signature_bytes = base64.b64decode(signature_b64)
        
        if isinstance(data, str):
            data = data.encode('utf-8')

        public_key.verify(
            signature_bytes,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    
    except InvalidSignature:
        return False
    
    except Exception as e:
        print(f"Signature verification error: {e}")
        return False
    
def encrypt_rsa(public_key_pem, message_bytes):
    """
    Encrypts data using a recipient's public RSA key.

    This function is used to encrypt symmetric keys before sending
    them to authorized peers.
    """
    public_key = load_public_key(public_key_pem)
    encrypted = public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_rsa(private_key, encrypted_b64):
    """
    Decrypts RSA-encrypted data using the local private key.

    This is used by peers to recover the symmetric key needed to decrypt
    the actual message content.
    """
    
    encrypted_bytes = base64.b64decode(encrypted_b64)
    decrypted = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted # Retorna os bytes da chave simétrica