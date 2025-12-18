"""
peer_node.py


This file implements a secure peer in a decentralized database system.
Each peer acts both as a client and a server: it stores data locally, accepts
connections from other peers, and propagates encrypted PUT operations across
the network. Peers communicate directly with each other, using a discovery
server only to find currently available peers.

The peer ensures confidentiality, integrity, and authenticity of data by using
hybrid cryptography (symmetric encryption for data and asymmetric encryption
for key distribution), as well as digital signatures.
"""

import socket
import threading
import json
import time
import sys
import os
from crypto_utils import (
    verify_signature, sign_data, generate_key_pair, serialize_public_key, 
    encrypt_data, decrypt_data, generate_symmetric_key, 
    encrypt_rsa, decrypt_rsa, create_and_split_identity, load_identity_with_shares
)
from database import LocalDatabase

class PeerNode:
    """
    Represents a single peer in the system.

    Each PeerNode:
    - owns a local database
    - owns an RSA key pair
    - listens for incoming TCP connections
    - sends encrypted and signed data to other peers
    """

    def __init__(self, host, port, my_id, discovery_ip, discovery_port, password):
        """
        Initialize a single peer in the P2P secure distributed database.


        Parameters:
        - host: IP address to bind the peer server to
        - port: TCP port where the peer will listen
        - my_id: logical identifier of the peer (e.g., "Alice")
        - discovery_ip: IP address of the discovery server
        - discovery_port: port of the discovery server
        """
        self.host = host
        self.port = port
        self.my_id = my_id
        self.discovery_ip = discovery_ip
        self.discovery_port = discovery_port
        
        # Local persistent database for this peer
        self.db = LocalDatabase(my_id, folder="peer_data")
        self.sse_index = {} 

        # --- IDENTITY MANAGEMENT (SSS) ---
        print(f"[{my_id}] Checking identity secure storage...")
        if os.path.exists("keys/identity.enc"):
            print(" -> Identity found. Reconstructing with Secret Sharing...")
            self.private_key, self.public_key = load_identity_with_shares(password)

            if self.private_key is None:
                print("CRITICAL ERROR: Wrong password or corrupted key shares.")
                sys.exit(1)
            else:
                print(" -> Success! Private key reconstructed in memory.")
        
        else:
            print(" -> No identity found. Creating new one with SSS protection...")
            self.private_key, self.public_key = create_and_split_identity(password)
            print(" -> Identity created and protected (Threshold 2-of-2).")

        self.pub_key_str = serialize_public_key(self.public_key)

    # ==============================================================
    # SERVER-SIDE LOGIC
    # ==============================================================
    
    def start_server(self):
        """
        Start the TCP server that listens for incoming connections
        from other peers.
        """
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.bind((self.host, self.port))
            server.listen()
            print(f"[SERVIDOR] Peer {self.my_id} listening in {self.host}:{self.port}")
            
            while True:
                conn, addr = server.accept()
                thread = threading.Thread(target=self.handle_request, args=(conn, addr))
                thread.start()
        except Exception as e:
            print(f"[SERVER ERROR] {e}")

    def handle_request(self, conn, addr):
        """
        Handle an incoming TCP request from another peer.

        The request is expected to be a JSON object with a 'type' field. Supported types:
        - PING
        - PUT
        - SEARCH (placeholder for future work)
        """
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
            print(f"[HANDLER ERROR] {e}")
        finally:
            conn.close()

    def handle_put(self, request, conn):
        """
        Handle an incoming PUT request.

        Steps:
        1. Verify the digital signature
        2. If valid, store the encrypted data locally
        3. Reply with status OK or DENIED
        """
        print(f"\n[RECEIVED] PUT from {request.get('sender_id', 'Unknown')}")
        
        # Verify signature to ensure authenticity and integrity
        valid = verify_signature(
            request['sender_pub_key'], 
            request['encrypted_data'], 
            request['signature']
        )
        
        if valid:
            doc_id = request['doc_id']
            sender = request.get("sender_id", "Unknown")
            table = request["table"]  # NEW: table support
            key = request["key"]
            
            # CORREÇÃO: Guardar 'encrypted_keys' (plural) em vez de singular
            storage_item = {
                "sender_id": sender,
                "table": table,
                "key": key,  # store the user key
                "doc_id": doc_id,  # internal doc ID
                "encrypted_data": request['encrypted_data'],
                "encrypted_keys": request['encrypted_keys'] # Dicionário {PeerID: Chave}
            }
            
            self.db.put(doc_id, storage_item, table) 
            
            if self.my_id in request['encrypted_keys']:
                auth_status = "AUTHORIZED recipient"
            else:
                auth_status = "NOT authorized (ciphertext only)"

            print(
                print(f"VALID from {sender} | table='{table}', key='{key}', doc_id='{doc_id}' | {auth_status}")
                )
            
            conn.send(json.dumps({"status": "OK"}).encode())
        else:
            print(" -> INVALID SIGNATURE. Rejected.")
            conn.send(json.dumps({"status": "DENIED"}).encode())

    def handle_search(self, request, conn):
        print(f"\n[RECEIVED] SEARCH")
        conn.send(json.dumps({"status": "OK", "results": []}).encode())

    # ==============================================================
    # CLIENT-SIDE LOGIC
    # ==============================================================

    def register_discovery(self):
        """
        Register this peer with the discovery server.

        Sends peer ID, listening port, and public key.
        """
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
            print(f"[DISCOVERY ERROR] It was not possible to connect: {e}")

    def get_peers(self):
        """
        Request the list of currently active peers from the discovery server.

        Returns:
        - dictionary mapping peer_id -> (ip, port, public_key)
        """
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

    def broadcast_data(self, message_text, target_peer_ids, table_name, key):
        """
        Broadcast encrypted data (PUT) to all peers, storing it under a specific key (doc_id)
        in the chosen table. Decryption access is granted only to specific receivers.

        Parameters:
        - message_text: plaintext value to send (v)
        - target_peer_ids: list of peer IDs allowed to decrypt the data
        - table_name: name of the table to store the key-value pair
        - doc_id: key under which the value is stored (k)
        """

        all_peers = self.get_peers()
        valid_targets = [pid for pid in target_peer_ids if pid in all_peers]
        
        if not valid_targets:
            print("[ERROR] No receivers found.")
            return

        doc_id = f"doc-{self.my_id}-{int(time.time())}"

        print(f"[BROADCAST] Sending '{key}' to: {valid_targets} in table '{table_name}'")

        try:
            # 1. Generate symmetric key
            file_key = generate_symmetric_key()

            # 2. Encrypt message with symmetric key
            encrypted_bytes = encrypt_data(file_key, message_text)
            encrypted_data_str = encrypted_bytes.decode('utf-8')

            # 3. Sign encrypted data
            signature = sign_data(self.private_key, encrypted_data_str)

            # 4. Encrypt symmetric key for each authorized peer
            keys_map = {}
            for pid in valid_targets:
                target_pub_key = all_peers[pid][2]
                keys_map[pid] = encrypt_rsa(target_pub_key, file_key)

            # 5. Create payload
            payload = {
                "type": "PUT",
                "sender_id": self.my_id,
                "table": table_name,  # NEW: include table
                "key": key,  # User provided key
                "doc_id": doc_id,  
                "encrypted_data": encrypted_data_str,
                "encrypted_keys": keys_map, # Dicionário com chaves para cada destinatário
                "signature": signature,
                "sender_pub_key": self.pub_key_str
            }
            
            # 6. Send payload to all peers
            for peer_id, info in all_peers.items():
                if peer_id == self.my_id: continue
                threading.Thread(
                    target=self._send_thread_worker, 
                    args=(info[0], int(info[1]), payload, peer_id)
                ).start()
                
        except Exception as e:
            print(f"[BROADCAST ERROR] {e}")

    def _send_thread_worker(self, ip, port, payload, peer_id):
        """
        Worker thread that sends a PUT payload to a single peer.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, port))
            s.send(json.dumps(payload).encode())
            s.close()
        except:
            print(f" -> Failure sending to {peer_id}")

# ==============================================================
# COMMAND-LINE INTERFACE
# ==============================================================

def main():
    discovery_ip = input("Insert Discovery Server's IP (Default: 127.0.0.1): ")
    if not discovery_ip: discovery_ip = "127.0.0.1"
    discovery_port = 5000 

    my_id = input("Insert peer's ID (ex: Alice): ")
    my_port_input = input("Insert peer's port number (ex: 6001): ")
    my_port = int(my_port_input) if my_port_input else 6001

    password = input(f"Enter password for {my_id}'s secure vault: ")
    
    node = PeerNode('0.0.0.0', my_port, my_id, discovery_ip, discovery_port, password)
    
    # Start server in background
    server_thread = threading.Thread(target=node.start_server, daemon=True)
    server_thread.start()
    time.sleep(1)

    # Register with discovery server
    node.register_discovery()
    
    while True:
        print("\n--- MENU P2P SECURE DB ---")
        print("1. List Peers")
        print("2. Send Data (Multi-Receiver)")
        print("3. Exit")
        print("4. See my local data")
        choice = input("Choose: ")
        
        if choice == '1':
            peers = node.get_peers()
            print("Peers Online:", list(peers.keys()))
            
        elif choice == '2':
            peers = node.get_peers()
            if not peers:
                print("No peer found.")
                continue
            
            print("Available peers:", list(peers.keys()))
            targets_input = input("Recipient (separate with commas): ")
            target_list = [t.strip() for t in targets_input.split(',') if t.strip()]
            
            if not target_list:
                print("Empty recipient list.")
                continue

            table_name = input("Table name: ").strip()
            key = input("Key (k): ").strip()
            value = input("Value (v): ")

            node.broadcast_data(value, target_list, table_name=table_name, key=key)
                
        elif choice == '3':
            print("Shutting down...")
            sys.exit()

        elif choice == '4':
            try:
                table = input("Table name: ").strip()
                key = input("Key (k): ").strip()

                table_data = node.db.get_table(table)  # get full table
                if not table_data:
                    print("Table not found or empty.")
                    continue

                # Find the doc that matches the user-provided key
                matched_doc = None
                for doc_id, item in table_data.items():
                    if item.get('key') == key:
                        matched_doc = (doc_id, item)
                        break

                if not matched_doc:
                    print("Not found.")
                    continue

                # CORREÇÃO: Lógica de leitura para Multi-Recipient
                doc_id, item = matched_doc
                keys_map = item['encrypted_keys']
                sender = item.get('sender_id', '?')
                
                if node.my_id in keys_map:
                    # Sou um destinatário!
                    my_enc_key = keys_map[node.my_id]
                    sym_key = decrypt_rsa(node.private_key, my_enc_key)
                    plaintext = decrypt_data(sym_key, item['encrypted_data'].encode('utf-8'))
                    print(f"Key: {key} | Doc ID: {doc_id} | Content: {plaintext}")
                else:
                    # Tenho o ficheiro mas não sou o destinatário
                    print(f"Key: {key} | Doc ID: {doc_id} | [ACCESS DENIED] (Encrypted file)")
                
            except Exception as e:
                print(f"ID: {doc_id} | Failed to read: {e}")

if __name__ == "__main__":
    main()