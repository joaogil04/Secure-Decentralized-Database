"""
crypto_utils.py

This file contains all cryptographic primitives and utility functions used in the system.

It implements:
1. Symmetric Encryption: AES-128 (CBC mode) with HMAC (via Fernet) for data confidentiality and integrity.
2. Asymmetric Encryption: RSA-2048 (OAEP padding) for secure key distribution (Digital Envelope).
3. Digital Signatures: RSA-PSS for non-repudiation and authenticity.
4. Key Management: Shamir's Secret Sharing (SSS) for splitting private keys.
5. Searchable Encryption (SSE): HKDF and HMAC-based trapdoor generation.

Dependencies: 'cryptography' library (PyCA).
"""

import os
import base64
import secrets
import hmac
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# ==============================================================
# SHAMIR SECRET SHARING (SSS) CONSTANTS & MATH
# ==============================================================
# We use a finite field GF(p) defined by a large Mersenne Prime.
# 2^521 - 1 is chosen to accommodate secrets larger than 32 bytes (e.g., serialized keys).
PRIME = 2**521 - 1

def _eval_poly(poly, x):
    """
    Evaluates a polynomial at x within the finite field GF(PRIME).
    Used to generate shares.
    """
    result = 0
    for coeff in reversed(poly):
        result = (result * x + coeff) % PRIME
    return result

def _lagrange_interpolation(x, x_s, y_s):
    """
    Reconstructs the secret (f(0)) using Lagrange Interpolation.
    Given k points, it finds the unique polynomial of degree k-1.
    """
    k = len(x_s)
    secret = 0
    for j in range(k):
        numerator = 1
        denominator = 1
        for m in range(k):
            if m == j: continue
            numerator = (numerator * (x - x_s[m])) % PRIME
            denominator = (denominator * (x_s[j] - x_s[m])) % PRIME
        
        # Calculate modular inverse using Fermat's Little Theorem
        lagrange_term = y_s[j] * numerator * pow(denominator, PRIME - 2, PRIME)
        secret = (secret + lagrange_term) % PRIME
    return secret

def split_secret(secret_bytes, t, n):
    """
    Splits a secret into n shares using Shamir's Secret Sharing Scheme.
    Requires t shares to reconstruct the original secret.
    
    - param secret_bytes: The secret to protect.
    - param t: Threshold (minimum shares needed).
    - param n: Total number of shares to generate.
    - return: List of tuples (x, y).
    """
    secret_int = int.from_bytes(secret_bytes, byteorder='big')
    if secret_int >= PRIME:
        raise ValueError("Secret too large for the defined finite field.")

    # Generate random coefficients for a polynomial of degree t-1
    # The free coefficient (f(0)) is the secret itself.
    coeffs = [secret_int] + [secrets.randbelow(PRIME) for _ in range(t - 1)]
    
    shares = []
    for i in range(1, n + 1):
        x = i
        y = _eval_poly(coeffs, x)
        shares.append((x, y))
    return shares

def recover_secret(shares):
    """
    Recovers the secret bytes from a list of shares using Lagrange Interpolation.
    """
    if len(shares) < 2: 
        raise ValueError("Not enough shares to reconstruct the secret.")
    
    x_s, y_s = zip(*shares)
    secret_int = _lagrange_interpolation(0, x_s, y_s)
    
    # Convert integer back to bytes
    # Fernet keys are 32 bytes, but we allow flexibility
    try:
        return secret_int.to_bytes(32, byteorder='big')
    except:
        # Fallback for dynamic length calculation
        return secret_int.to_bytes((secret_int.bit_length() + 7) // 8, byteorder='big')
    
# ==============================================================
# KEY FILE MANAGEMENT & KDF
# ==============================================================

def save_file(data, filename, folder="keys"):
    """Saves raw bytes to a file, ensuring the directory exists."""
    if not os.path.exists(folder):
        os.makedirs(folder)
    filepath = os.path.join(folder, filename)
    with open(filepath, "wb") as f:
        f.write(data)
    return filepath

def load_file(filename, folder="keys"):
    """Loads raw bytes from a file."""
    filepath = os.path.join(folder, filename)
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    return open(filepath, "rb").read()

def derive_key_from_password(password, salt=None):
    """
    Derives a cryptographic key from a password using PBKDF2-HMAC-SHA256.
    This strengthens the password against brute-force attacks.
    """
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
    Creates a new Identity (RSA Keypair) and protects it using SSS.
    
    Process:
    1. Generate RSA Key Pair.
    2. Encrypt Private Key with a random symmetric 'Master Key'.
    3. Split 'Master Key' into 2 shares:
       - Share 1: Stored in plaintext on disk (Proof of Possession).
       - Share 2: Encrypted with the user's password (Proof of Knowledge).
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
    
    # Share 2: Encrypted with Password derived key
    pass_key, salt = derive_key_from_password(password)
    f_pass = Fernet(base64.urlsafe_b64encode(pass_key))
    
    y_bytes = str(share_pass[1]).encode()
    encrypted_share_pass = f_pass.encrypt(y_bytes)
    
    final_blob = salt + b"::" + encrypted_share_pass
    save_file(final_blob, "share_pass.dat")
    
    return private_key, public_key

def load_identity_with_shares(password):
    """
    Reconstructs the private key by combining the Disk Share and Password Share.
    This implements a Two-Factor protection (Something you have + Something you know).
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
        
        # Reconstruct Master Key using SSS
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
# ==============================================================

def generate_symmetric_key():
    """Generates a new Fernet key (AES-128 in CBC mode with SHA256 HMAC)."""
    return Fernet.generate_key()

def encrypt_data(key, plaintext):
    """Encrypts data using Fernet (Authenticated Encryption)."""
    f = Fernet(key)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    return f.encrypt(plaintext)

def decrypt_data(key, ciphertext):
    """Decrypts data and verifies HMAC integrity."""
    f = Fernet(key)
    return f.decrypt(ciphertext).decode('utf-8')

# ==============================================================
# ASYMMETRIC CRYPTOGRAPHY (RSA)
# ==============================================================

def generate_key_pair():
    """Generates RSA 2048-bit key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """Serializes Public Key to PEM format (X.509 SubjectPublicKeyInfo)."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

def load_public_key(pem_string):
    """Loads Public Key from PEM string."""
    return serialization.load_pem_public_key(pem_string.encode('utf-8'))

def sign_data(private_key, data):
    """
    Signs data using RSA-PSS padding with SHA256.
    PSS is preferred over PKCS1v1.5 for better security proofs.
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
    """Verifies RSA-PSS signature."""
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
    except (InvalidSignature, Exception):
        return False
    
def encrypt_rsa(public_key_pem, message_bytes):
    """
    Encrypts small data (e.g., symmetric keys) using RSA-OAEP with SHA256.
    Used for the Digital Envelope scheme.
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
    """Decrypts RSA-OAEP encrypted data."""
    encrypted_bytes = base64.b64decode(encrypted_b64)
    return private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ==============================================================
# SEARCHABLE SYMMETRIC ENCRYPTION (SSE)
# ==============================================================

# Shared cluster key for distributed search.
# In a production system, this should be securely negotiated.
CLUSTER_SEARCH_KEY = b'PROJECT_DPS_CLUSTER_KEY_2025_FIXED'

def derive_search_key(master_key=None, salt=None):
    """
    Derives a secure search key using HKDF (HMAC-based Key Derivation Function).
    
    - param master_key: The input key material. If None, uses the CLUSTER_SEARCH_KEY
                        to allow global search across peers.
    """
    if master_key is None:
        master_key = CLUSTER_SEARCH_KEY

    if salt is None:
        salt = b'SSE_SEARCH_SALT_DEFAULT'
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'search_trapdoor_derivation',
        backend=default_backend()
    )
    return hkdf.derive(master_key)

def generate_trapdoor(search_key, keyword):
    """
    Generates a deterministic trapdoor for a keyword using HMAC-SHA256.
    
    This acts as a secure search token: 
    Trapdoor = HMAC(SearchKey, Keyword)
    """
    if isinstance(keyword, str):
        keyword = keyword.encode('utf-8')
    
    trapdoor = hmac.new(search_key, keyword, 'sha256').digest()
    return base64.b64encode(trapdoor).decode('utf-8')

def create_search_index(search_key, keyword, doc_id):
    """
    Helper to create SSE index entries.
    
    Returns:
        (trapdoor, encrypted_entry)
        
    Note: The 'encrypted_entry' (HMAC of ID) is generated for robustness but
    current database implementation may only use the 'trapdoor' for indexing.
    """
    trapdoor = generate_trapdoor(search_key, keyword)
    
    if isinstance(doc_id, str):
        doc_id = doc_id.encode('utf-8')
    
    # Create an integrity-protected index entry
    index_entry = hmac.new(
        search_key, 
        trapdoor.encode('utf-8') + doc_id, 
        'sha256'
    ).digest()
    
    return trapdoor, base64.b64encode(index_entry).decode('utf-8')

def verify_search_match(search_key, keyword, doc_id, stored_entry):
    """
    Verifies if a specific document matches a keyword using the encrypted entry.
    Uses constant-time comparison to prevent timing attacks.
    """
    _, computed_entry = create_search_index(search_key, keyword, doc_id)
    return secrets.compare_digest(stored_entry, computed_entry)