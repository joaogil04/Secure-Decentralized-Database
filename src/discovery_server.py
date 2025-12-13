"""
discovery_server.py


This file implements a simple peer discovery service. The server's purpose is to:
- keep track of active peers in the network;
- allow peers to register themselves;
- allow peers to discover other available peers;
- remove peers that become unavailable.

The server acts similarly to a DNS service and is not involved in PUT or GET
operations.
"""

import socket
import threading
import json
import time

# ==============================================================
# SERVER CONFIGURATION
# ==============================================================

HOST = '0.0.0.0'
PORT = 5000  # TCP port used by the discovery service

# Dictionary holding currently active peers
active_peers = {} # Format: {"peer_id": ("ip", port, "pub_key")}

# ==============================================================
# AVAILABILITY MONITORING (Slide 47 - Availability)
# ==============================================================

def monitor_peers():
    """
    Periodically checks whether registered peers are still reachable.

    Every 10S, the server tries to open a TCP connection to each peer.
    If a peer does not respond, it is assumed to be offline and removed from
    the active peers list.
    """

    print("[MONITOR] Heartbeat system started...")
    while True:
        time.sleep(10)
        peers_to_check = list(active_peers.items())  # Create a copy of the dictionary --> avoid issues of runtime modifications
        
        for peer_id, info in peers_to_check:
            # CORREÇÃO AQUI: Agora a lista tem 3 coisas (IP, Porta, Key)
            # Vamos buscar só o IP e Porta para o Ping
            ip = info[0]
            port = info[1]
            
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex((ip, int(port)))  # Try to connect to the peer
                
                if result == 0:
                    # Envia PING para não ser confundido com dados
                    s.send(json.dumps({"type": "PING"}).encode())
                    s.close()
                else:
                    raise Exception("Port unreachable")
            except:
                print(f"[REMOVED] Peer {peer_id} ({ip}:{port}) is offline.")
                if peer_id in active_peers:
                    del active_peers[peer_id]

# ==============================================================
# CLIENT REQUEST HANDLER
# ==============================================================

def handle_client(conn, addr):
    """
    Handles incoming connections from peers.

    Supported request types:
    - REGISTER: registers a new peer in the network
    - GET_PEERS: returns the list of active peers (excluding the requester)
    """

    print(f"[NEW CONNECTION] {addr} connected.")
    try:
        msg = conn.recv(4096).decode('utf-8') # Aumentei o buffer porque a Public Key é grande
        if not msg: return
        request = json.loads(msg)

        response = {}
        
        if request['type'] == 'REGISTER':
            # Register a new peer
            peer_id = request['peer_id']
            port = request['port']
            # CORREÇÃO AQUI: Ler a Public Key do pedido
            pub_key = request.get('pub_key', 'CHAVE_NAO_ENVIADA')
            
            # CORREÇÃO AQUI: Guardar IP, Porta E Chave Pública (3 elementos)
            active_peers[peer_id] = (addr[0], port, pub_key)
            
            print(f"[REGISTO] Peer {peer_id} in {addr[0]}:{port}")
            response = {"status": "SUCCESS", "message": "Registered"}

        elif request['type'] == 'GET_PEERS':
            # Return all peers except the requester
            requester_id = request.get('peer_id')
            others = {k: v for k, v in active_peers.items() if k != requester_id}
            response = {"status": "SUCCESS", "peers": others}

        # Send response back to peer
        conn.send(json.dumps(response).encode('utf-8'))
    
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        conn.close()

# ==============================================================
# SERVER BOOTSTRAP
# ==============================================================

def start():
    """
    Starts the discovery server and listens for incoming connections.

    A background thread is launched to monitor peer availability, while
    the main thread accepts new TCP connections.
    """

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[DISCOVERY] Listening on {HOST}:{PORT}")

    # Start availability monitor in the background
    monitor_thread = threading.Thread(target=monitor_peers, daemon=True)
    monitor_thread.start()

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start()