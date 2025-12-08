# discovery_server.py
import socket
import threading
import json
import time

# Configuração
HOST = '0.0.0.0'
PORT = 5000
active_peers = {} # Formato: {"peer_id": ("ip", port)}

# --- NOVA FUNÇÃO DE HEARTBEAT ---
def monitor_peers():
    print("[MONITOR] Sistema de Heartbeat iniciado...")
    while True:
        time.sleep(10) # Verifica a cada 10 segundos
        
        # Criar uma cópia da lista para não dar erro ao remover itens durante o loop
        peers_to_check = list(active_peers.items()) 
        
        for peer_id, address in peers_to_check:
            ip, port = address
            try:
                # Tenta conectar com um timeout curto (ex: 2 segundos)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((ip, int(port)))
                
                if result == 0:
                    # Conexão bem sucedida (Peer está vivo)
                    # Opcional: Enviar mensagem {"type": "PING"}
                    s.send(json.dumps({"type": "PING"}).encode())
                    s.close()
                else:
                    raise Exception("Porta fechada")
            
            except:
                print(f"[REMOVIDO] O peer {peer_id} ({ip}:{port}) não responde.")
                # Remover do dicionário oficial
                if peer_id in active_peers:
                    del active_peers[peer_id]

def handle_client(conn, addr):
    print(f"[NOVA CONEXÃO] {addr} conectado.")
    try:
        msg = conn.recv(1024).decode('utf-8')
        if not msg: return
        request = json.loads(msg)

        response = {}
        
        # Peer Regista-se
        if request['type'] == 'REGISTER':
            peer_id = request['peer_id']
            port = request['port']
            active_peers[peer_id] = (addr[0], port)
            print(f"[REGISTO] Peer {peer_id} em {addr[0]}:{port}")
            response = {"status": "SUCCESS", "message": "Registado"}

        # Peer pede lista de outros Peers
        elif request['type'] == 'GET_PEERS':
            # Retorna todos exceto o próprio solicitante
            requester_id = request.get('peer_id')
            others = {k: v for k, v in active_peers.items() if k != requester_id}
            response = {"status": "SUCCESS", "peers": others}

        conn.send(json.dumps(response).encode('utf-8'))
    
    except Exception as e:
        print(f"[ERRO] {e}")
    finally:
        conn.close()

def start():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[DISCOVERY] A escutar em {HOST}:{PORT}")

    monitor_thread = threading.Thread(target=monitor_peers, daemon=True)
    monitor_thread.start()

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start()