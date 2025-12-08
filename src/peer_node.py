import socket
import threading
import json
import time
import sys
# Certifica-te que tens o crypto_utils.py na mesma pasta
from crypto_utils import verify_signature, sign_data, generate_key_pair, serialize_public_key
from database import LocalDatabase

class PeerNode:
    # 1. CORREÇÃO: Receber e guardar o discovery_ip e port logo no início
    def __init__(self, host, port, my_id, discovery_ip, discovery_port):
        self.host = host
        self.port = port
        self.my_id = my_id
        self.discovery_ip = discovery_ip     # Guardar na classe
        self.discovery_port = discovery_port # Guardar na classe
        self.db = LocalDatabase(f"storage_{my_id}.json")
        self.sse_index = {}
        
        print(f"[{my_id}] A gerar chaves de encriptação...")
        self.private_key, self.public_key = generate_key_pair()
        self.pub_key_str = serialize_public_key(self.public_key)

    # --- PARTE SERVIDOR ---
    # 2. CORREÇÃO: start_server não precisa de argumentos, ele só trata de receber conexões
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
            encrypted_data = request['encrypted_data']
            
            self.db.put(doc_id, encrypted_data)
            
            print(f" -> Guardado no disco: {doc_id}")
            conn.send(json.dumps({"status": "OK"}).encode())
        else:
            print(" -> Assinatura INVÁLIDA. Rejeitado.")
            conn.send(json.dumps({"status": "DENIED"}).encode())

    def handle_search(self, request, conn):
        print(f"\n[RECEBIDO] SEARCH")
        conn.send(json.dumps({"status": "OK", "results": []}).encode())

    # --- PARTE CLIENTE ---
    
    # 3. CORREÇÃO: Removemos os argumentos daqui porque usamos self.discovery_ip
    def register_discovery(self):
        """Regista este peer no Discovery Server"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Usa as variáveis guardadas no __init__
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

    # 4. CORREÇÃO: Removemos os argumentos daqui também
    def get_peers(self):
        """Pede a lista de peers ao Discovery"""
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
        try:
            encrypted_blob = f"ENCRYPTED[{message_text}]" 
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
    # 5. CORREÇÃO: Pedimos os dados aqui e passamos APENAS para o construtor
    discovery_ip = input("Insira o IP do Discovery Server (Default: 127.0.0.1): ")
    if not discovery_ip: discovery_ip = "127.0.0.1"
    
    discovery_port = 5000 # Mantemos fixo ou podes pedir input também

    my_id = input("Insira o ID do Peer (ex: Alice): ")
    my_port = int(input("Insira a porta do Peer (ex: 6001): "))
    
    # Passamos tudo para a classe aqui
    node = PeerNode('0.0.0.0', my_port, my_id, discovery_ip, discovery_port)
    
    # 6. CORREÇÃO: Removemos args daqui. A função start_server já não precisa deles.
    server_thread = threading.Thread(target=node.start_server, daemon=True)
    server_thread.start()
    
    time.sleep(1)
    
    # Chamamos as funções sem argumentos (elas usam o self.discovery_ip)
    node.register_discovery()
    
    while True:
        print("\n--- MENU ---")
        print("1. Listar Peers (do Discovery)")
        print("2. Enviar Dados (PUT)")
        print("3. Sair")
        choice = input("Escolha: ")
        
        if choice == '1':
            peers = node.get_peers() # Já não dá erro de falta de argumentos
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