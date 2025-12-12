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
        self.host = host
        self.port = port
        self.my_id = my_id
        self.discovery_ip = discovery_ip
        self.discovery_port = discovery_port
        
        self.db = LocalDatabase(my_id, folder="peer_data")
        self.sse_index = {} 
        
        print(f"[{my_id}] A gerar chaves de encriptação (RSA)...")
        self.private_key, self.public_key = generate_key_pair()
        self.pub_key_str = serialize_public_key(self.public_key)

    # --- PARTE SERVIDOR ---
    def start_server(self):
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
        try:
            data = conn.recv(8192).decode('utf-8')
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
        print(f"\n[RECEBIDO] PUT de {request.get('sender_id', 'Unknown')}")
        
        valid = verify_signature(
            request['sender_pub_key'], 
            request['encrypted_data'], 
            request['signature']
        )
        
        if valid:
            doc_id = request['doc_id']
            
            # CORREÇÃO: Guardar 'encrypted_keys' (plural) em vez de singular
            storage_item = {
                "sender_id": request.get('sender_id'),
                "encrypted_data": request['encrypted_data'],
                "encrypted_keys": request['encrypted_keys'] # Dicionário {PeerID: Chave}
            }
            
            self.db.put(doc_id, storage_item)
            
            print(f" -> Assinatura VÁLIDA. Dados guardados: {doc_id}")
            conn.send(json.dumps({"status": "OK"}).encode())
        else:
            print(" -> Assinatura INVÁLIDA. Rejeitado.")
            conn.send(json.dumps({"status": "DENIED"}).encode())

    def handle_search(self, request, conn):
        print(f"\n[RECEBIDO] SEARCH")
        conn.send(json.dumps({"status": "OK", "results": []}).encode())

    # --- PARTE CLIENTE ---
    def register_discovery(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.discovery_ip, self.discovery_port))
            msg = {
                "type": "REGISTER",
                "peer_id": self.my_id,
                "port": self.port,
                "pub_key": self.pub_key_str
            }
            s.send(json.dumps(msg).encode())
            resp = json.loads(s.recv(1024).decode())
            print(f"[DISCOVERY] Registo: {resp['status']}")
            s.close()
        except Exception as e:
            print(f"[ERRO DISCOVERY] Não foi possível conectar: {e}")

    def get_peers(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.discovery_ip, self.discovery_port))
            msg = {"type": "GET_PEERS", "peer_id": self.my_id}
            s.send(json.dumps(msg).encode())
            
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

    def broadcast_data(self, message_text, target_peer_ids):
        """Envia para todos, com chaves específicas para os destinatários."""
        all_peers = self.get_peers()
        valid_targets = [pid for pid in target_peer_ids if pid in all_peers]
        
        if not valid_targets:
            print("[ERRO] Nenhum destinatário encontrado.")
            return

        print(f"[BROADCAST] A enviar para a rede. Acesso para: {valid_targets}")

        try:
            # 1. Criptografia Simétrica
            file_key = generate_symmetric_key()
            encrypted_bytes = encrypt_data(file_key, message_text)
            encrypted_data_str = encrypted_bytes.decode('utf-8')

            # 2. Assinatura
            signature = sign_data(self.private_key, encrypted_data_str)

            # 3. Múltiplos Envelopes (Dicionário de chaves)
            keys_map = {}
            for pid in valid_targets:
                target_pub_key = all_peers[pid][2]
                keys_map[pid] = encrypt_rsa(target_pub_key, file_key)

            # 4. Enviar
            doc_id = f"doc-{self.my_id}-{int(time.time())}"
            payload = {
                "type": "PUT",
                "sender_id": self.my_id,
                "doc_id": doc_id,
                "encrypted_data": encrypted_data_str,
                "encrypted_keys": keys_map, # Dicionário com chaves para cada destinatário
                "signature": signature,
                "sender_pub_key": self.pub_key_str
            }
            
            for peer_id, info in all_peers.items():
                if peer_id == self.my_id: continue
                threading.Thread(
                    target=self._send_thread_worker, 
                    args=(info[0], int(info[1]), payload, peer_id)
                ).start()
                
        except Exception as e:
            print(f"[ERRO BROADCAST] {e}")

    def _send_thread_worker(self, ip, port, payload, peer_id):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, port))
            s.send(json.dumps(payload).encode())
            s.close()
        except:
            print(f" -> Falha ao enviar para {peer_id}")

# --- MENU ---
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
        print("2. Enviar Dados (Multi-Destinatário)")
        print("3. Sair")
        print("4. Ver os meus dados locais")
        choice = input("Escolha: ")
        
        if choice == '1':
            peers = node.get_peers()
            print("Peers Online:", list(peers.keys()))
            
        elif choice == '2':
            peers = node.get_peers()
            if not peers:
                print("Nenhum peer encontrado.")
                continue
            
            print("Peers disponíveis:", list(peers.keys()))
            targets_input = input("Destinatários (separar por vírgula): ")
            target_list = [t.strip() for t in targets_input.split(',') if t.strip()]
            
            if target_list:
                msg = input("Mensagem: ")
                node.broadcast_data(msg, target_list)
            else:
                print("Lista vazia.")
                
        elif choice == '3':
            print("A encerrar...")
            sys.exit()

        elif choice == '4':
            print("\n--- MEUS DADOS LOCAIS ---")
            all_data = node.db.data 
            if not all_data:
                print("Vazio.")
            else:
                for doc_id, item in all_data.items():
                    try:
                        # CORREÇÃO: Lógica de leitura para Multi-Recipient
                        keys_map = item['encrypted_keys']
                        sender = item.get('sender_id', '?')
                        
                        if node.my_id in keys_map:
                            # Sou um destinatário!
                            my_enc_key = keys_map[node.my_id]
                            sym_key = decrypt_rsa(node.private_key, my_enc_key)
                            plaintext = decrypt_data(sym_key, item['encrypted_data'].encode('utf-8'))
                            print(f"ID: {doc_id} | De: {sender} | Conteúdo: {plaintext}")
                        else:
                            # Tenho o ficheiro mas não sou o destinatário
                            print(f"ID: {doc_id} | De: {sender} | [ACESSO NEGADO] (Ficheiro cifrado)")
                            
                    except Exception as e:
                        print(f"ID: {doc_id} | Erro ao ler: {e}")

if __name__ == "__main__":
    main()