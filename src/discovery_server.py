import socket
import threading
import json
import time

# Configuração
HOST = '0.0.0.0'
PORT = 5000
active_peers = {} # Formato: {"peer_id": ("ip", port, "pub_key")}

# --- MONITOR DE DISPONIBILIDADE (Slide 47 - Availability) ---
def monitor_peers():
    """
    Tenta conectar a todos os peers a cada 10s.
    Se um peer não responder, é removido da lista.
    """
    print("[MONITOR] Sistema de Heartbeat iniciado...")
    while True:
        time.sleep(10) 
        peers_to_check = list(active_peers.items()) 
        
        for peer_id, info in peers_to_check:
            # CORREÇÃO AQUI: Agora a lista tem 3 coisas (IP, Porta, Key)
            # Vamos buscar só o IP e Porta para o Ping
            ip = info[0]
            port = info[1]
            
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((ip, int(port)))
                
                if result == 0:
                    # Envia PING para não ser confundido com dados
                    s.send(json.dumps({"type": "PING"}).encode())
                    s.close()
                else:
                    raise Exception("Porta fechada")
            except:
                print(f"[REMOVIDO] O peer {peer_id} ({ip}:{port}) não responde.")
                if peer_id in active_peers:
                    del active_peers[peer_id]

def handle_client(conn, addr):
    print(f"[NOVA CONEXÃO] {addr} conectado.")
    try:
        msg = conn.recv(4096).decode('utf-8') # Aumentei o buffer porque a Public Key é grande
        if not msg: return
        request = json.loads(msg)

        response = {}
        
        if request['type'] == 'REGISTER':
            peer_id = request['peer_id']
            port = request['port']
            # CORREÇÃO AQUI: Ler a Public Key do pedido
            pub_key = request.get('pub_key', 'CHAVE_NAO_ENVIADA')
            
            # CORREÇÃO AQUI: Guardar IP, Porta E Chave Pública (3 elementos)
            active_peers[peer_id] = (addr[0], port, pub_key)
            
            print(f"[REGISTO] Peer {peer_id} em {addr[0]}:{port}")
            response = {"status": "SUCCESS", "message": "Registado"}

        elif request['type'] == 'GET_PEERS':
            requester_id = request.get('peer_id')
            # Retorna todos exceto o próprio
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

    # Iniciar monitor em background
    monitor_thread = threading.Thread(target=monitor_peers, daemon=True)
    monitor_thread.start()

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start()