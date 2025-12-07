# crypto_utils.py
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import base64

# 1. Gerar chaves (Para o Cliente usar no arranque)
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# 2. Serializar Chaves (Para enviar pela rede/guardar em disco)
def serialize_public_key(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

def load_public_key(pem_string):
    return serialization.load_pem_public_key(
        pem_string.encode('utf-8')
    )

# 3. Assinar Dados (Cliente faz isto ANTES de enviar o PUT)
def sign_data(private_key, data):
    # Se os dados forem string, converte para bytes
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
    # Retorna em Base64 para ser fácil enviar em JSON
    return base64.b64encode(signature).decode('utf-8')

# 4. Verificar Assinatura (O SERVIDOR faz isto ao receber o PUT)
def verify_signature(public_key_pem, data, signature_b64):
    """
    Retorna True se a assinatura for válida, False caso contrário.
    """
    try:
        # Carregar a chave pública do formato string
        public_key = load_public_key(public_key_pem)
        
        # Descodificar a assinatura de Base64 para bytes
        signature_bytes = base64.b64decode(signature_b64)
        
        # Garantir que os dados são bytes
        if isinstance(data, str):
            data = data.encode('utf-8')

        # Tentar verificar
        public_key.verify(
            signature_bytes,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True # Se não der erro, é válido
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Erro na verificação: {e}")
        return False