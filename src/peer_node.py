import socket
import threading
import json
import time
import sys
from crypto_utils import (
    verify_signature, sign_data, generate_key_pair, serialize_public_key, 
    load_key_from_file, encrypt_data, decrypt_data, generate_symmetric_key, 
    encrypt_rsa, decrypt_rsa
)
from database import LocalDatabase

class PeerNode:
    def __init__(self, host, port, my_id, discovery_ip, discovery_port):
        """
        Inicializa o Peer com identidade RSA e base de dados local.
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
        print(f"[{my_id}] A gerar chaves de encriptação (RSA)...")
        self.private_key, self.public_key = generate_key_pair()
        self.pub_key_str = serialize_public_key(self.public_key)

        # Nota: Removemos a carga da 'shared_secret.key' porque vamos usar
        # Encriptação Híbrida (chaves geradas por mensagem).

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
                thread = threading.Thread(target=self.handle_request, args=(conn, addr))
                thread.start()
        except Exception as e:
            print(f"[ERRO SERVIDOR] {e}")

    def handle_request(self, conn, addr):
        """Processa pedidos PUT, SEARCH, PING."""
        try:
            data = conn.recv(8192).decode('utf-8') # Buffer maior para chaves RSA
            if not data: return
            request = json.loads(data)

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
        Recebe e guarda dados cifrados.
        Verifica assinatura para garantir Integridade e Autenticidade.
        """
        print(f"\n[RECEBIDO] PUT de {request.get('sender_id', 'Unknown')}")
        
        valid = verify_signature(
            request['sender_pub_key'], 
            request['encrypted_data'], 
            request['signature']
        )
        
        if valid:
            doc_id = request['doc_id']
            # Agora guardamos o objeto completo (dados + chave cifrada)
            # para podermos desencriptar depois.
            storage_item = {
                "encrypted_data": request['encrypted_data'],
                "encrypted_key": request['encrypted_key']
            }
            
            self.db.put(doc_id, storage_item)
            
            print(f" -> Assinatura VÁLIDA. Envelope Digital guardado: {doc_id}")
            conn.send(json.dumps({"status": "OK"}).encode())
        else:
            print(" -> Assinatura INVÁLIDA. Rejeitado.")
            conn.send(json.dumps({"status": "DENIED"}).encode())

    def handle_search(self, request, conn):
        print(f"\n[RECEBIDO] SEARCH")
        conn.send(json.dumps({"status": "OK", "results": []}).encode())

    # --- PARTE CLIENTE ---
    
    def register_discovery(self):
        """Regista no Discovery, enviando também a Public Key."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.discovery_ip, self.discovery_port))
            msg = {
                "type": "REGISTER",
                "peer_id": self.my_id,
                "port": self.port,
                "pub_key": self.pub_key_str # Agora anunciamos a chave pública!
            }
            s.send(json.dumps(msg).encode())
            resp = json.loads(s.recv(1024).decode())
            print(f"[DISCOVERY] Registo: {resp['status']}")
            s.close()
        except Exception as e:
            print(f"[ERRO DISCOVERY] Não foi possível conectar: {e}")

    def get_peers(self):
        """Pede lista de peers (incluindo chaves públicas) ao Discovery."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.discovery_ip, self.discovery_port))
            msg = {"type": "GET_PEERS", "peer_id": self.my_id}
            s.send(json.dumps(msg).encode())
            
            # Buffer grande porque recebe chaves públicas
            data = b""
            while True:
                part = s.recv(4096)
                data += part
                if len(part) < 4096: break
            
            resp = json.loads(data.decode())
            s.close()
            return resp.get('peers', {})
        except Exception as e:
            print(f"[ERRO GET_PEERS] {e}")
            return {}

    def send_data_to_peer(self, target_ip, target_port, message_text, target_pub_key_str):
        """
        Envia dados usando Encriptação Híbrida (Envelope Digital).
        1. Gera chave simétrica aleatória (AES).
        2. Encripta dados com AES.
        3. Encripta chave AES com RSA (Public Key do Destino).
        4. Assina dados encriptados com RSA (Minha Private Key).
        """
        try:
            # 1. Gerar chave única para este ficheiro
            file_key = generate_symmetric_key()
            
            # 2. Encriptar dados (AES)
            encrypted_bytes = encrypt_data(file_key, message_text)
            encrypted_data_str = encrypted_bytes.decode('utf-8')

            # 3. Encriptar a chave (RSA - Envelope)
            # target_pub_key_str vem do Discovery Server
            encrypted_key_str = encrypt_rsa(target_pub_key_str, file_key)

            # 4. Assinar (Integridade/Autenticidade)
            signature = sign_data(self.private_key, encrypted_data_str)
            
            payload = {
                "type": "PUT",
                "sender_id": self.my_id,
                "doc_id": f"doc-{int(time.time())}",
                "encrypted_data": encrypted_data_str,
                "encrypted_key": encrypted_key_str,  # A chave cifrada vai aqui
                "signature": signature,
                "sender_pub_key": self.pub_key_str
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
    
    node = PeerNode('0.0.0.0', my_port, my_id, discovery_ip, discovery_port)
    
    server_thread = threading.Thread(target=node.start_server, daemon=True)
    server_thread.start()
    
    time.sleep(1)
    node.register_discovery()
    
    while True:
        print("\n--- MENU P2P SECURE DB ---")
        print("1. Listar Peers")
        print("2. Enviar Dados (Encriptação Híbrida)")
        print("3. Sair")
        print("4. Ver os meus dados locais (Desencriptar)")
        choice = input("Escolha: ")
        
        if choice == '1':
            peers = node.get_peers()
            # Mostra apenas IDs para não poluir o ecrã
            print("Peers Online:", list(peers.keys()))
            
        elif choice == '2':
            peers = node.get_peers()
            if not peers:
                print("Nenhum peer encontrado.")
                continue
            
            print("Peers disponíveis:", list(peers.keys()))
            target_id = input("Para quem quer enviar? (ID): ")
            
            if target_id in peers:
                peer_info = peers[target_id]
                ip = peer_info[0]   # Agora o Discovery guarda [ip, port, pub_key]
                port = peer_info[1]
                pub_key = peer_info[2] # Extrair a chave pública do destino
                
                msg = input("Mensagem para guardar: ")
                node.send_data_to_peer(ip, port, msg, pub_key)
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
                for doc_id, item in all_data.items():
                    # item agora é um dicionário: {"encrypted_data": "...", "encrypted_key": "..."}
                    try:
                        # 1. Abrir o Envelope Digital
                        enc_key_b64 = item['encrypted_key']
                        sym_key = decrypt_rsa(node.private_key, enc_key_b64)
                        
                        # 2. Desencriptar os dados
                        enc_data = item['encrypted_data']
                        plaintext = decrypt_data(sym_key, enc_data.encode('utf-8'))
                        
                        print(f"ID: {doc_id} | Conteúdo: {plaintext}")
                        
                    except Exception as e:
                        # Se falhar, é porque a mensagem não foi encriptada para mim
                        print(f"ID: {doc_id} | [BLOQUEADO] Não tenho a chave para ler este ficheiro.")

if __name__ == "__main__":
    main()