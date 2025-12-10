from crypto_utils import generate_symmetric_key, save_key_to_file

print("A gerar chave simétrica partilhada...")
key = generate_symmetric_key()

# A função agora cria a pasta 'keys' sozinha se não existir
filepath = save_key_to_file(key, "shared_secret.key", folder="keys")

print(f"Chave guardada com sucesso em: {filepath}")
print("IMPORTANTE: Garante que todos os peers têm acesso a este ficheiro!")