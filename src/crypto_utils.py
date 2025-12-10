import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

# --- GESTÃO DE FICHEIROS E PASTAS ---

def save_key_to_file(key, filename, folder="keys"):
    """Guarda bytes num ficheiro, criando a pasta se necessário."""
    if not os.path.exists(folder):
        os.makedirs(folder)
    
    filepath = os.path.join(folder, filename)
    with open(filepath, "wb") as key_file:
        key_file.write(key)
    return filepath

def load_key_from_file(filename, folder="keys"):
    """Lê bytes de um ficheiro."""
    filepath = os.path.join(folder, filename)
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Ficheiro não encontrado: {filepath}")
    return open(filepath, "rb").read()

# --- CRIPTOGRAFIA SIMÉTRICA (AES-128 + HMAC) ---
# Slide 56: Authenticated Encryption (Encrypt-then-MAC)

def generate_symmetric_key():
    return Fernet.generate_key()

def encrypt_data(key, plaintext):
    """Encripta texto usando Fernet (AES)."""
    f = Fernet(key)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    return f.encrypt(plaintext)

def decrypt_data(key, ciphertext):
    """Desencripta e verifica integridade."""
    f = Fernet(key)
    return f.decrypt(ciphertext).decode('utf-8')

# --- CRIPTOGRAFIA ASSIMÉTRICA (RSA-PSS) ---
# Slide 62: Digital Signatures & Public Key Encryption

def generate_key_pair():
    """Gera par de chaves RSA 2048-bit."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """Converte chave pública para formato PEM (string para enviar na rede)."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

def load_public_key(pem_string):
    """Lê chave pública de formato PEM."""
    return serialization.load_pem_public_key(pem_string.encode('utf-8'))

def sign_data(private_key, data):
    """Assina dados usando RSA-PSS com SHA256."""
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
    """Verifica se a assinatura corresponde aos dados e à chave pública."""
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
        print(f"Erro verificação: {e}")
        return False
    
def encrypt_rsa(public_key_pem, message_bytes):
    """Encripta a chave simétrica com a Chave Pública do destino."""
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
    """Desencripta a chave simétrica com a minha Chave Privada."""
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