import socket
import threading
import json
import time
import sys
# Certifica-te que tens o crypto_utils.py na mesma pasta
from crypto_utils import verify_signature, sign_data, generate_key_pair, serialize_public_key

# Configuração do Discovery
DISCOVERY_IP = '127.0.0.1'
DISCOVERY_PORT = 5000

class PeerNode:
    def __init__(self, host, port, my_id):
        self.host = host
        self.port = port
        self.my_id = my_id
        self.storage = {} 
        self.sse_index = {}
        
        # Gerar chaves RSA ao iniciar
        print(f"[{my_id}] A gerar chaves de encriptação...")
        self.private_key, self.public_key = generate_key_pair()
        self.pub_key_str = serialize_public_key(self.public_key)

    # --- PARTE SERVIDOR (Ouvir outros peers) ---
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
            data = conn.recv(4096).decode('utf-8')
            if not data: return
            request = json.loads(data)
            
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
        # 1. Verificar Assinatura (Integridade e Autenticidade)
        valid = verify_signature(
            request['sender_pub_key'], 
            request['encrypted_data'], 
            request['signature']
        )
        
        if valid:
            self.storage[request['doc_id']] = request['encrypted_data']
            print(" -> Assinatura VÁLIDA. Dados guardados.")
            conn.send(json.dumps({"status": "OK"}).encode())
        else:
            print(" -> Assinatura INVÁLIDA. Rejeitado.")
            conn.send(json.dumps({"status": "DENIED"}).encode())

    def handle_search(self, request, conn):
        # (Lógica simples para teste, aqui implementarias o SSE real)
        print(f"\n[RECEBIDO] SEARCH")
        conn.send(json.dumps({"status": "OK", "results": []}).encode())

    # --- PARTE CLIENTE (Falar com Discovery e outros Peers) ---
    
    def register_discovery(self):
        """Regista este peer no Discovery Server"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((DISCOVERY_IP, DISCOVERY_PORT))
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
        """Pede a lista de peers ao Discovery"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((DISCOVERY_IP, DISCOVERY_PORT))
            msg = {"type": "GET_PEERS", "peer_id": self.my_id}
            s.send(json.dumps(msg).encode())
            resp = json.loads(s.recv(4096).decode())
            s.close()
            return resp.get('peers', {})
        except:
            return {}

    def send_data_to_peer(self, target_ip, target_port, message_text):
        """Envia um PUT para outro peer"""
        try:
            # 1. Simular Encriptação (AES seria aqui)
            encrypted_blob = f"ENCRYPTED[{message_text}]" 
            
            # 2. Assinar os dados (Integridade)
            signature = sign_data(self.private_key, encrypted_blob)
            
            payload = {
                "type": "PUT",
                "sender_id": self.my_id,
                "doc_id": f"doc-{int(time.time())}",
                "encrypted_data": encrypted_blob,
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
    my_id = input("Insira o ID do Peer (ex: Alice): ")
    my_port = int(input("Insira a porta do Peer (ex: 6001): "))
    
    node = PeerNode('0.0.0.0', my_port, my_id)
    
    # 1. Iniciar servidor numa thread separada (para não bloquear o menu)
    server_thread = threading.Thread(target=node.start_server, daemon=True)
    server_thread.start()
    
    # Dar tempo ao servidor para arrancar
    time.sleep(1)
    
    # 2. Registar automaticamente no Discovery
    node.register_discovery()
    
    # 3. Menu Interativo
    while True:
        print("\n--- MENU ---")
        print("1. Listar Peers (do Discovery)")
        print("2. Enviar Dados (PUT)")
        print("3. Sair")
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

if __name__ == "__main__":
    main()