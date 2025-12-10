import socket
import threading
import json
import time
import sys
from crypto_utils import verify_signature, sign_data, generate_key_pair, serialize_public_key, load_key_from_file, encrypt_data, decrypt_data
from database import LocalDatabase

class PeerNode:
    def __init__(self, host, port, my_id, discovery_ip, discovery_port):
        """
        Inicializa o Peer.
        - Cria a identidade (Chaves RSA).
        - Carrega a chave simétrica partilhada (AES).
        - Inicializa a base de dados local.
        """
        self.host = host
        self.port = port
        self.my_id = my_id
        self.discovery_ip = discovery_ip
        self.discovery_port = discovery_port
        
        # Base de Dados Persistente (Requirement: Access to local state)
        self.db = LocalDatabase(my_id, folder="peer_data")
        self.sse_index = {} # (Futuro: Índice para pesquisa SSE)
        
        # 1. Identidade e Autenticidade (Slide 61 - Public-key Encryption)
        # Geramos um par de chaves RSA. A Public Key será a nossa "Identidade".
        print(f"[{my_id}] A gerar chaves de encriptação (RSA)...")
        self.private_key, self.public_key = generate_key_pair()
        self.pub_key_str = serialize_public_key(self.public_key)

        # 2. Confidencialidade (Slide 56 - Authenticated Encryption)
        # Carregamos a chave AES partilhada para encriptar os dados (Fase 1).
        try:
            self.symmetric_key = load_key_from_file("shared_secret.key", folder="keys")
            print(f"[{my_id}] Chave simétrica (AES) carregada com sucesso.")
        except FileNotFoundError:
            print(f"[{my_id}] ERRO CRÍTICO: 'keys/shared_secret.key' não encontrado!")
            print("Execute o 'setup_keys.py' primeiro.")
            sys.exit(1)

    # --- PARTE SERVIDOR (Ouvir outros peers) ---
    def start_server(self):
        """Inicia a thread que escuta por conexões de outros peers."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.bind((self.host, self.port))
            server.listen()
            print(f"[SERVIDOR] Peer {self.my_id} à escuta em {self.host}:{self.port}")
            
            while True:
                conn, addr = server.accept()
                # Para cada conexão, criamos uma nova thread para não bloquear o servidor
                thread = threading.Thread(target=self.handle_request, args=(conn, addr))
                thread.start()
        except Exception as e:
            print(f"[ERRO SERVIDOR] {e}")

    def handle_request(self, conn, addr):
        """Processa os pedidos recebidos (PUT, SEARCH, PING)."""
        try:
            data = conn.recv(4096).decode('utf-8')
            if not data: return
            request = json.loads(data)

            # Heartbeat do Discovery (Slide 47 - Availability)
            if request.get('type') == 'PING':
                return
            
            if request['type'] == 'PUT':
                self.handle_put(request, conn)
            elif request['type'] == 'SEARCH':
                self.handle_search(request, conn)
        except Exception as e:
            print(f"[ERRO HANDLER] {e}")
        finally:
            conn.close()

    def handle_put(self, request, conn):
        """
        Recebe dados para guardar.
        Implementa verificação de Integridade e Autenticidade (Slide 49 - MACs/Signatures).
        """
        print(f"\n[RECEBIDO] PUT de {request.get('sender_id', 'Unknown')}")
        
        # A Assinatura garante que os dados não foram alterados E que quem enviou possui a chave privada.
        valid = verify_signature(
            request['sender_pub_key'], 
            request['encrypted_data'], 
            request['signature']
        )
        
        if valid:
            doc_id = request['doc_id']
            encrypted_data = request['encrypted_data']
            
            # Guardamos o blob encriptado sem saber o conteúdo (Privacidade).
            self.db.put(doc_id, encrypted_data)
            
            print(f" -> Assinatura VÁLIDA. Guardado no disco: {doc_id}")
            conn.send(json.dumps({"status": "OK"}).encode())
        else:
            print(" -> Assinatura INVÁLIDA ou Dados Corrompidos. Rejeitado.")
            conn.send(json.dumps({"status": "DENIED"}).encode())

    def handle_search(self, request, conn):
        """Placeholder para pesquisa."""
        print(f"\n[RECEBIDO] SEARCH")
        conn.send(json.dumps({"status": "OK", "results": []}).encode())

    # --- PARTE CLIENTE (Falar com Discovery e outros Peers) ---
    
    def register_discovery(self):
        """Regista este peer no Discovery Server."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.discovery_ip, self.discovery_port))
            msg = {
                "type": "REGISTER",
                "peer_id": self.my_id,
                "port": self.port
            }
            s.send(json.dumps(msg).encode())
            resp = json.loads(s.recv(1024).decode())
            print(f"[DISCOVERY] Registo: {resp['status']}")
            s.close()
        except Exception as e:
            print(f"[ERRO DISCOVERY] Não foi possível conectar: {e}")

    def get_peers(self):
        """Pede a lista de peers online ao Discovery."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.discovery_ip, self.discovery_port))
            msg = {"type": "GET_PEERS", "peer_id": self.my_id}
            s.send(json.dumps(msg).encode())
            resp = json.loads(s.recv(4096).decode())
            s.close()
            return resp.get('peers', {})
        except:
            return {}

    def send_data_to_peer(self, target_ip, target_port, message_text):
        """
        Envia dados para outro peer com Segurança Total.
        1. Encriptação (AES) - Confidencialidade.
        2. Assinatura (RSA) - Integridade e Autenticidade.
        """
        try:
            # 1. Encriptar (Authenticated Encryption - Slide 52)
            encrypted_bytes = encrypt_data(self.symmetric_key, message_text)
            encrypted_blob = encrypted_bytes.decode('utf-8')

            # 2. Assinar o Criptograma (Slide 62 - Digital Signatures)
            # Assinamos o que enviamos (o blob encriptado) para garantir que ninguém o altera.
            signature = sign_data(self.private_key, encrypted_blob)
            
            payload = {
                "type": "PUT",
                "sender_id": self.my_id,
                "doc_id": f"doc-{int(time.time())}",
                "encrypted_data": encrypted_blob,
                "signature": signature,
                "sender_pub_key": self.pub_key_str # Enviamos a chave pública para validação
            }
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, int(target_port)))
            s.send(json.dumps(payload).encode())
            resp = s.recv(1024).decode()
            print(f"[ENVIO] Resposta do Peer: {resp}")
            s.close()
        except Exception as e:
            print(f"[ERRO ENVIO] {e}")

# --- MENU PRINCIPAL ---
def main():
    discovery_ip = input("Insira o IP do Discovery Server (Default: 127.0.0.1): ")
    if not discovery_ip: discovery_ip = "127.0.0.1"
    
    discovery_port = 5000 

    my_id = input("Insira o ID do Peer (ex: Alice): ")
    my_port_input = input("Insira a porta do Peer (ex: 6001): ")
    my_port = int(my_port_input) if my_port_input else 6001
    
    # Instanciar o Nó
    node = PeerNode('0.0.0.0', my_port, my_id, discovery_ip, discovery_port)
    
    # Iniciar o servidor em background
    server_thread = threading.Thread(target=node.start_server, daemon=True)
    server_thread.start()
    
    time.sleep(1)
    
    # Registar na rede
    node.register_discovery()
    
    # Loop do Menu
    while True:
        print("\n--- MENU P2P SECURE DB ---")
        print("1. Listar Peers (do Discovery)")
        print("2. Enviar Dados (PUT Seguro)")
        print("3. Sair")
        print("4. Ver os meus dados locais (Desencriptados)")
        choice = input("Escolha: ")
        
        if choice == '1':
            peers = node.get_peers()
            print("Peers Online:", peers)
            
        elif choice == '2':
            peers = node.get_peers()
            if not peers:
                print("Nenhum peer encontrado.")
                continue
            
            print("Peers disponíveis:", list(peers.keys()))
            target_id = input("Para quem quer enviar? (ID): ")
            
            if target_id in peers:
                ip, port = peers[target_id]
                msg = input("Mensagem para guardar: ")
                node.send_data_to_peer(ip, port, msg)
            else:
                print("Peer não existe.")
                
        elif choice == '3':
            print("A encerrar...")
            sys.exit()

        elif choice == '4':
            print("\n--- MEUS DADOS LOCAIS ---")
            all_data = node.db.data 
            if not all_data:
                print("Base de dados vazia.")
            else:
                for doc_id, enc_data in all_data.items():
                    try:
                        # Tenta desencriptar com a chave simétrica partilhada
                        plaintext = decrypt_data(node.symmetric_key, enc_data.encode('utf-8'))
                        print(f"ID: {doc_id} | Conteúdo: {plaintext}")
                    except Exception as e:
                        print(f"ID: {doc_id} | ERRO: Integridade falhou ou chave errada.")

if __name__ == "__main__":
    main()