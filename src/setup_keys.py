from crypto_utils import generate_symmetric_key, save_key_to_file

print("--- SETUP DE CHAVES ---")
print("A gerar chave simétrica partilhada (AES)...")

key = generate_symmetric_key()

# Guarda automaticamente na pasta 'keys/'
filepath = save_key_to_file(key, "shared_secret.key", folder="keys")

print(f"\n[SUCESSO] Chave guardada em: {filepath}")
print("IMPORTANTE: Se for correr o projeto em vários PCs,")
print("copie a pasta 'keys' para todos eles!")