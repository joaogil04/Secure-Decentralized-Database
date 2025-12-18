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
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature
import secrets

# ==============================================================
# SHAMIR SECRET SHARING CONSTANTS & MATH
# ==============================================================
# Mersenne Prime 2^127 - 1 (Sufficient for 32-byte keys)
PRIME = 2**521 - 1

def _eval_poly(poly, x):
    """Evaluates polynomial at x."""
    result = 0
    for coeff in reversed(poly):
        result = (result * x + coeff) % PRIME
    return result

def _lagrange_interpolation(x, x_s, y_s):
    """Reconstructs the secret (f(0)) using Lagrange interpolation."""
    k = len(x_s)
    secret = 0
    for j in range(k):
        numerator = 1
        denominator = 1
        for m in range(k):
            if m == j: continue
            numerator = (numerator * (x - x_s[m])) % PRIME
            denominator = (denominator * (x_s[j] - x_s[m])) % PRIME
        
        # Modular inverse
        lagrange_term = y_s[j] * numerator * pow(denominator, PRIME - 2, PRIME)
        secret = (secret + lagrange_term) % PRIME
    return secret

def split_secret(secret_bytes, t, n):
    """
    Splits a secret (bytes) into n shares, requiring t to recover.
    Returns a list of tuples (x, y).
    """
    secret_int = int.from_bytes(secret_bytes, byteorder='big')
    if secret_int >= PRIME:
        raise ValueError("Secret too large for this prime.")

    # Generate random coefficients for polynomial of degree t-1
    coeffs = [secret_int] + [secrets.randbelow(PRIME) for _ in range(t - 1)]
    
    shares = []
    for i in range(1, n + 1):
        x = i
        y = _eval_poly(coeffs, x)
        shares.append((x, y))
    return shares

def recover_secret(shares):
    """
    Recovers the secret bytes from a list of shares [(x, y), ...].
    """
    if len(shares) < 2: 
        raise ValueError("Not enough shares.")
    
    x_s, y_s = zip(*shares)
    secret_int = _lagrange_interpolation(0, x_s, y_s)
    
    # Convert back to 32 bytes (standard for Fernet keys)
    try:
        return secret_int.to_bytes(32, byteorder='big')
    except:
        # Fallback padding calculation
        return secret_int.to_bytes((secret_int.bit_length() + 7) // 8, byteorder='big')
    
# ==============================================================
# KEY FILE MANAGEMENT & KDF
# ==============================================================

def save_file(data, filename, folder="keys"):
    if not os.path.exists(folder):
        os.makedirs(folder)
    filepath = os.path.join(folder, filename)
    with open(filepath, "wb") as f:
        f.write(data)
    return filepath

def load_file(filename, folder="keys"):
    filepath = os.path.join(folder, filename)
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    return open(filepath, "rb").read()

def derive_key_from_password(password, salt=None):
    """Derives a secure AES key from a password using PBKDF2."""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return key, salt

# ==============================================================
# IDENTITY MANAGEMENT (SSS INTEGRATION)
# ==============================================================

def create_and_split_identity(password):
    """
    1. Generates RSA Key Pair.
    2. Encrypts Private Key with a random Master Key.
    3. Splits Master Key into 2 shares (Disk + Password).
    """
    # 1. Generate RSA
    private_key, public_key = generate_key_pair()
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # 2. Generate Master Key & Encrypt Identity
    master_key = Fernet.generate_key() # 32 bytes url-safe base64
    master_key_bytes = base64.urlsafe_b64decode(master_key) # 32 bytes raw
    
    f = Fernet(master_key)
    encrypted_identity = f.encrypt(pem_private)
    
    # 3. Split Master Key (Threshold 2, Total 2)
    shares = split_secret(master_key_bytes, 2, 2)
    share_disk = shares[0] # (1, y1)
    share_pass = shares[1] # (2, y2)
    
    # 4. Save Files
    save_file(encrypted_identity, "identity.enc")
    
    # Share 1: Plaintext on disk
    save_file(f"{share_disk[0]}:{share_disk[1]}".encode(), "share_disk.dat")
    
    # Share 2: Encrypted with Password
    pass_key, salt = derive_key_from_password(password)
    f_pass = Fernet(base64.urlsafe_b64encode(pass_key))
    
    y_bytes = str(share_pass[1]).encode()
    encrypted_share_pass = f_pass.encrypt(y_bytes)
    
    final_blob = salt + b"::" + encrypted_share_pass
    save_file(final_blob, "share_pass.dat")
    
    return private_key, public_key

def load_identity_with_shares(password):
    """
    Reconstructs the private key using the disk share + password share.
    """
    try:
        # Load files
        encrypted_identity = load_file("identity.enc")
        share_disk_data = load_file("share_disk.dat").decode()
        share_pass_data = load_file("share_pass.dat")
        
        # Parse Disk Share
        sx, sy = share_disk_data.split(':')
        share_disk = (int(sx), int(sy))
        
        # Decrypt Password Share
        salt, enc_y = share_pass_data.split(b"::")
        pass_key, _ = derive_key_from_password(password, salt)
        f_pass = Fernet(base64.urlsafe_b64encode(pass_key))
        
        y_pass = int(f_pass.decrypt(enc_y).decode())
        share_pass = (2, y_pass)
        
        # Reconstruct Master Key
        shares = [share_disk, share_pass]
        master_key_bytes = recover_secret(shares)
        master_key = base64.urlsafe_b64encode(master_key_bytes)
        
        # Decrypt RSA Private Key
        f = Fernet(master_key)
        pem_private = f.decrypt(encrypted_identity)
        
        private_key = serialization.load_pem_private_key(
            pem_private,
            password=None
        )
        return private_key, private_key.public_key()
        
    except Exception as e:
        print(f"Failed to reconstruct identity: {e}")
        return None, None

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