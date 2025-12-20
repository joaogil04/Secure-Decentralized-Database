"""
discovery_server.py

This file implements the Peer Discovery Service (Directory Service).

In a pure P2P network, peers might need a bootstrap mechanism to find each other.
This server acts as a centralized repository of active peers, similar to a 
DNS service or a Tracker in BitTorrent.

It ensures:
1. Registration: New peers announce their presence (IP, Port, Public Key).
2. Discovery: Peers can request a list of currently active neighbors.
3. Availability (Failure Detection): A background thread performs active 
   health checks (heartbeats) to remove offline peers.

NOTE: This server NEVER handles data storage (PUT/GET). It only manages metadata.
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
# Structure: { "peer_id": ("ip", "port", "public_key_pem") }
active_peers = {} 

# ==============================================================
# AVAILABILITY MONITORING (Failure Detection)
# ==============================================================

def monitor_peers():
    """
    Implements an Active Failure Detection mechanism (Heartbeat).
    
    Periodically (every 10s), the server attempts to establish a TCP connection 
    to every registered peer. If a peer is unreachable, it is considered crashed 
    or offline and is removed from the directory to maintain consistency.
    """
    print("[MONITOR] Heartbeat failure detection system started...")
    
    while True:
        time.sleep(10)
        # Create a copy of items to avoid RuntimeError during dictionary modification
        peers_to_check = list(active_peers.items())  
        
        for peer_id, info in peers_to_check:
            ip = info[0]
            port = info[1]
            # info[2] is the Public Key, not needed for ping
            
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2) # Short timeout for quick detection
                result = s.connect_ex((ip, int(port)))
                
                if result == 0:
                    # Send a PING packet so the peer knows it's just a check
                    s.send(json.dumps({"type": "PING"}).encode())
                    s.close()
                else:
                    raise Exception("Port unreachable")
            except:
                print(f"[REMOVED] Peer {peer_id} ({ip}:{port}) is unreachable/offline.")
                if peer_id in active_peers:
                    del active_peers[peer_id]

# ==============================================================
# CLIENT REQUEST HANDLER
# ==============================================================

def handle_client(conn, addr):
    """
    Handles incoming TCP connections from peers.

    Supported protocol messages:
    - REGISTER: Peer announces its ID, Port, and Public Key.
    - GET_PEERS: Peer requests the list of other active nodes.
    """
    print(f"[NEW CONNECTION] {addr} connected.")
    try:
        # Buffer size 4096 to accommodate large RSA Public Keys
        msg = conn.recv(4096).decode('utf-8') 
        if not msg: return
        
        request = json.loads(msg)
        response = {}
        
        if request['type'] == 'REGISTER':
            # 1. Extract details
            peer_id = request['peer_id']
            port = request['port']
            # Critical: Store Public Key for Hybrid Encryption distribution
            pub_key = request.get('pub_key', 'KEY_NOT_SENT')
            
            # 2. Update Directory
            # Storing tuple: (IP Address, Port, RSA Public Key)
            active_peers[peer_id] = (addr[0], port, pub_key)
            
            print(f"[REGISTERED] Peer '{peer_id}' at {addr[0]}:{port}")
            response = {"status": "SUCCESS", "message": "Successfully registered"}

        elif request['type'] == 'GET_PEERS':
            # Return list of peers excluding the requester itself
            requester_id = request.get('peer_id')
            others = {k: v for k, v in active_peers.items() if k != requester_id}
            
            response = {"status": "SUCCESS", "peers": others}

        # Send JSON response
        conn.send(json.dumps(response).encode('utf-8'))
    
    except Exception as e:
        print(f"[ERROR] Handling client: {e}")
    finally:
        conn.close()

# ==============================================================
# SERVER BOOTSTRAP
# ==============================================================

def start():
    """
    Main entry point. Starts the TCP server and the background monitor thread.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[DISCOVERY] Directory Service running on {HOST}:{PORT}")

    # Start the Heartbeat monitor in a background thread (daemon)
    monitor_thread = threading.Thread(target=monitor_peers, daemon=True)
    monitor_thread.start()

    # Main loop for accepting connections
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    start()