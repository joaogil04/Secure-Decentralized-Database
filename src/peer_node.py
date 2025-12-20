"""
peer_node.py

This file implements a secure peer in a decentralized database system.

Architecture:
Each peer acts as both a client and a server (P2P Model):
1. Server: Listens for TCP connections to receive PUT (storage) and SEARCH requests.
2. Client: Connects to other peers to propagate data and query the network.
3. Discovery: Uses a central Directory Service only to find active peers (IP/Port).

Security Mechanisms:
- Confidentiality: Hybrid Encryption (AES for data, RSA for key distribution).
- Integrity/Authenticity: Digital Signatures (RSA-PSS).
- Privacy: Searchable Symmetric Encryption (SSE) for privacy-preserving queries.
- Identity Protection: Shamir's Secret Sharing (SSS) for private key storage.
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
    encrypt_rsa, decrypt_rsa, create_and_split_identity, load_identity_with_shares,
    derive_search_key, generate_trapdoor, create_search_index,
    CLUSTER_SEARCH_KEY # Imported to ensure all peers use the same derivation base
)
from database import LocalDatabase

class PeerNode:
    """
    Represents a single peer node in the network.

    Responsibilities:
    - Managing local persistent storage (LocalDatabase).
    - Managing cryptographic identity (RSA Keys).
    - Handling network protocols (PUT, GET, SEARCH).
    """

    def __init__(self, host, port, my_id, discovery_ip, discovery_port, password):
        """
        Initialize the peer node.

        - param host: Local IP to bind.
        - param port: Local TCP port.
        - param my_id: Unique identifier (e.g., "Alice").
        - param discovery_ip: Discovery Server IP.
        - param discovery_port: Discovery Server Port.
        - param password: User password to unlock the private key (SSS).
        """
        self.host = host
        self.port = port
        self.my_id = my_id
        self.discovery_ip = discovery_ip
        self.discovery_port = discovery_port
        
        # Local persistent database
        self.db = LocalDatabase(my_id, folder="peer_data")

        # --- IDENTITY MANAGEMENT (Shamir's Secret Sharing) ---
        print(f"[{my_id}] Checking secure identity storage...")
        if os.path.exists("keys/identity.enc"):
            print(" -> Identity found. Reconstructing with Secret Sharing...")
            self.private_key, self.public_key = load_identity_with_shares(password)

            if self.private_key is None:
                print("CRITICAL ERROR: Incorrect password or corrupted key shares.")
                sys.exit(1)
            else:
                print(" -> Success! Private key reconstructed in memory.")
        
        else:
            print(" -> No identity found. Creating new one with SSS protection...")
            self.private_key, self.public_key = create_and_split_identity(password)
            print(" -> Identity created and protected (Threshold 2-of-2).")

        self.pub_key_str = serialize_public_key(self.public_key)

        # Initialize SSE Search Key (Derived from the Cluster Key)
        # This ensures all peers generate the same trapdoors for the same keywords.
        self.search_master_key = derive_search_key(CLUSTER_SEARCH_KEY)

    # ==============================================================
    # SERVER-SIDE LOGIC
    # ==============================================================
    
    def start_server(self):
        """
        Starts the TCP server to listen for incoming P2P connections.
        """
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server.bind((self.host, self.port))
            server.listen()
            print(f"[SERVER] Peer {self.my_id} listening on {self.host}:{self.port}")
            
            while True:
                conn, addr = server.accept()
                thread = threading.Thread(target=self.handle_request, args=(conn, addr))
                thread.start()
        except Exception as e:
            print(f"[SERVER ERROR] {e}")

    def handle_request(self, conn, addr):
        """
        Dispatches incoming requests based on the message type.
        
        Supported Types:
        - PUT: Store encrypted data.
        - SEARCH: Perform a privacy-preserving keyword search.
        - PING: Liveness check.
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
        Processes a PUT request.
        
        Security Checks:
        1. Verifies the Digital Signature using the sender's Public Key.
        2. Stores the data if the signature is valid.
        """
        print(f"\n[RECEIVED] PUT from {request.get('sender_id', 'Unknown')}")
        
        # Verify Integrity and Authenticity
        valid = verify_signature(
            request['sender_pub_key'], 
            request['encrypted_data'], 
            request['signature']
        )
        
        if valid:
            doc_id = request['doc_id']
            sender = request.get("sender_id", "Unknown")
            table = request["table"]
            key = request["key"]
            
            storage_item = {
                "sender_id": sender,
                "table": table,
                "key": key,
                "doc_id": doc_id,
                "encrypted_data": request['encrypted_data'],
                "encrypted_keys": request['encrypted_keys'] # Map: PeerID -> Encrypted Symmetric Key
            }
            
            self.db.put(doc_id, storage_item, table) 
            
            # Index trapdoors for SSE (Privacy-Preserving Search)
            # We index incoming data so we can answer search queries later.
            if 'trapdoors' in request:
                for keyword, trapdoor in request['trapdoors'].items():
                    self.db.put_search_index(table, trapdoor, doc_id)

            # Index the file key (filename) trapdoor as well
            if 'key_trapdoor' in request:
                self.db.put_search_index(table, request['key_trapdoor'], doc_id)
            
            # Check access status for logging
            if self.my_id in request['encrypted_keys']:
                auth_status = "AUTHORIZED recipient"
            else:
                auth_status = "NOT authorized (ciphertext storage only)"

            print(f"VALID from {sender} | table='{table}', key='{key}' | {auth_status}")
            conn.send(json.dumps({"status": "OK"}).encode())
        else:
            print(" -> INVALID SIGNATURE. Rejected.")
            conn.send(json.dumps({"status": "DENIED"}).encode())

    def handle_search(self, request, conn):
        """
        Processes a SEARCH request.
        
        SSE Mechanism:
        - Receives a 'trapdoor' (hash), not the plaintext keyword.
        - Checks the local Inverted Index for matches.
        - Returns matching Document IDs.
        """
        print(f"\n[RECEIVED] SEARCH from {request.get('sender_id', 'Unknown')}")
        
        table_name = request.get('table')
        trapdoor = request.get('trapdoor')
        mode = request.get('mode', 'docs')  # 'docs' or 'tables'

        if not trapdoor:
            conn.send(json.dumps({"status": "ERROR", "message": "Missing trapdoor"}).encode())
            return

        # Mode: Search for Tables containing the key
        if mode == 'tables':
            tables = self.db.search_tables_by_trapdoor(trapdoor)
            response = {"status": "OK", "mode": "tables", "tables": tables, "count": len(tables)}
            print(f" -> Found {len(tables)} table(s) containing trapdoor")
            conn.send(json.dumps(response).encode())
            return

        # Mode: Search for Documents inside a specific table
        if not table_name:
            conn.send(json.dumps({"status": "ERROR", "message": "Missing table"}).encode())
            return

        matching_docs = self.db.search_by_trapdoor(table_name, trapdoor)
        response = {
            "status": "OK",
            "table": table_name,
            "results": matching_docs,
            "count": len(matching_docs)
        }
        print(f" -> Found {len(matching_docs)} document(s)")
        conn.send(json.dumps(response).encode())

    # ==============================================================
    # CLIENT-SIDE LOGIC
    # ==============================================================

    def register_discovery(self):
        """Registers this peer with the Discovery Server."""
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
            print(f"[DISCOVERY] Registration: {resp['status']}")
            s.close()
        except Exception as e:
            print(f"[DISCOVERY ERROR] Connection failed: {e}")

    def get_peers(self):
        """Fetches the list of active peers from the Discovery Server."""
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
            print(f"[GET_PEERS ERROR] {e}")
            return {}

    def broadcast_data(self, message_text, target_peer_ids, table_name, key, store_locally=False):
        """
        Encrypts and propagates data (PUT) to the network.

        Steps:
        1. Encrypt data with a random Symmetric Key (AES).
        2. Sign the ciphertext with RSA Private Key.
        3. Encrypt the Symmetric Key for each recipient using their Public Keys.
        4. Generate SSE Trapdoors for searchability.
        5. Send payload to all peers.
        """
        all_peers = self.get_peers()
        valid_targets = [pid for pid in target_peer_ids if pid in all_peers]
        
        if not valid_targets:
            print("[ERROR] No valid recipients found.")
            return

        doc_id = f"doc-{self.my_id}-{int(time.time())}"
        print(f"[BROADCAST] Sending '{key}' to: {valid_targets} in table '{table_name}'")

        try:
            # 1. Generate Symmetric Key
            file_key = generate_symmetric_key()

            # 2. Encrypt Data
            encrypted_bytes = encrypt_data(file_key, message_text)
            encrypted_data_str = encrypted_bytes.decode('utf-8')

            # 3. Sign Data
            signature = sign_data(self.private_key, encrypted_data_str)

            # 4. Encrypt Symmetric Key for recipients (Digital Envelope)
            keys_map = {}
            for pid in valid_targets:
                target_pub_key = all_peers[pid][2]
                keys_map[pid] = encrypt_rsa(target_pub_key, file_key)
            
            # If storing locally, encrypt the key for myself too
            if store_locally:
                my_encrypted_key = encrypt_rsa(self.pub_key_str, file_key)
                keys_map[self.my_id] = my_encrypted_key

            # 5. Create Payload
            payload = {
                "type": "PUT",
                "sender_id": self.my_id,
                "table": table_name,
                "key": key,
                "doc_id": doc_id,  
                "encrypted_data": encrypted_data_str,
                "encrypted_keys": keys_map,
                "signature": signature,
                "sender_pub_key": self.pub_key_str
            }

            # 6. Generate SSE Trapdoors
            keywords = message_text.split()
            trapdoors = {} 
            for keyword in keywords:
                # Generate robust trapdoor
                trapdoor, _ = create_search_index(self.search_master_key, keyword, doc_id)
                trapdoors[keyword] = trapdoor

                if store_locally:
                    self.db.put_search_index(table_name, trapdoor, doc_id)
            
            # Generate trapdoor for the File Key (filename)
            key_trapdoor = generate_trapdoor(self.search_master_key, key)
            if store_locally:
                self.db.put_search_index(table_name, key_trapdoor, doc_id)
            
            # Attach trapdoors to payload
            payload['trapdoors'] = trapdoors
            payload['key_trapdoor'] = key_trapdoor
            
            # 7. Broadcast
            for peer_id, info in all_peers.items():
                if peer_id == self.my_id: continue
                threading.Thread(
                    target=self._send_thread_worker, 
                    args=(info[0], int(info[1]), payload, peer_id)
                ).start()

            # 8. Local Storage (if requested)
            if store_locally:
                storage_item = {
                    "sender_id": self.my_id,
                    "table": table_name,
                    "key": key,
                    "doc_id": doc_id,
                    "encrypted_data": encrypted_data_str,
                    "encrypted_keys": keys_map 
                }
                self.db.put(doc_id, storage_item, table_name)
                print(f"[LOCAL] File '{key}' and indexes saved locally.")
            else:
                print(f"[LOCAL] File sent but NOT saved locally.")
                
        except Exception as e:
            print(f"[BROADCAST ERROR] {e}")

    def _send_thread_worker(self, ip, port, payload, peer_id):
        """Helper thread to send data to a specific peer."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((ip, port))
            s.send(json.dumps(payload).encode())
            s.close()
        except:
            print(f" -> Failure sending to {peer_id}")

    def search_keyword(self, keyword, table_name):
        """
        Performs a Local SSE Search.
        """
        trapdoor = generate_trapdoor(self.search_master_key, keyword)
        matching_docs = self.db.search_by_trapdoor(table_name, trapdoor)
        
        if not matching_docs:
            print(f"[SEARCH] No documents found for '{keyword}' in table '{table_name}'")
            return
        
        print(f"[SEARCH] Found {len(matching_docs)} document(s) matching '{keyword}':")
        
        table_data = self.db.get_table(table_name)
        for doc_id in matching_docs:
            if doc_id in table_data:
                item = table_data[doc_id]
                key = item.get('key', 'N/A')
                sender = item.get('sender_id', '?')
                print(f"  - Doc ID: {doc_id} | Key: {key} | From: {sender}")

    def search_distributed(self, keyword, table_name):
        """
        Performs a Distributed SSE Search across all active peers.
        """
        print(f"\n[DISTRIBUTED SEARCH] Searching '{keyword}' in table '{table_name}'")
        
        trapdoor = generate_trapdoor(self.search_master_key, keyword)
        
        # 1. Local Search
        local_results = self.db.search_by_trapdoor(table_name, trapdoor)
        aggregated_results = {self.my_id: local_results}
        print(f" -> Local search: {len(local_results)} document(s)")
        
        # 2. Remote Search
        all_peers = self.get_peers()
        search_request = {
            "type": "SEARCH",
            "sender_id": self.my_id,
            "table": table_name,
            "trapdoor": trapdoor
        }
        
        for peer_id, info in all_peers.items():
            if peer_id == self.my_id: continue
            
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((info[0], int(info[1])))
                s.send(json.dumps(search_request).encode())
                
                # Receive response (handle fragmentation)
                response_data = b""
                while True:
                    part = s.recv(4096)
                    if not part: break
                    response_data += part
                s.close()
                
                if response_data:
                    response = json.loads(response_data.decode())
                    if response.get('status') == 'OK':
                        results = response.get('results', [])
                        aggregated_results[peer_id] = results
                        print(f" -> Remote search on {peer_id}: {len(results)} document(s)")
                    
            except socket.timeout:
                print(f" -> {peer_id}: timeout")
            except Exception as e:
                print(f" -> {peer_id}: error")
        
        # 3. Display Results
        total_results = sum(len(docs) for docs in aggregated_results.values())
        print(f"\n[RESULT] Total: {total_results} document(s) found across network")
        
        for peer_id, doc_ids in aggregated_results.items():
            if doc_ids:
                print(f"\nFrom {peer_id}:")
                if peer_id == self.my_id:
                    # Local: Show full details
                    table_data = self.db.get_table(table_name)
                    for doc_id in doc_ids:
                        if doc_id in table_data:
                            item = table_data[doc_id]
                            key = item.get('key', 'N/A')
                            print(f"  - Doc ID: {doc_id} | Key: {key}")
                else:
                    # Remote: Show IDs (Content is encrypted/not retrieved yet)
                    for doc_id in doc_ids:
                        print(f"  - Doc ID: {doc_id} (remote)")
        
        return aggregated_results

    def search_key_tables_distributed(self, key):
        """
        Distributed search to find which Tables contain a specific File Key.
        """
        print(f"\n[DISTRIBUTED KEY-TABLE SEARCH] Searching key '{key}' across network")
        trapdoor = generate_trapdoor(self.search_master_key, key)

        # 1. Local Search
        local_tables = self.db.search_tables_by_trapdoor(trapdoor)
        aggregated = {self.my_id: local_tables}
        print(f" -> Local: {len(local_tables)} table(s)")

        # 2. Remote Search
        all_peers = self.get_peers()
        search_request = {
            "type": "SEARCH",
            "sender_id": self.my_id,
            "trapdoor": trapdoor,
            "mode": "tables"
        }

        for peer_id, info in all_peers.items():
            if peer_id == self.my_id: continue

            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                s.connect((info[0], int(info[1])))
                s.send(json.dumps(search_request).encode())

                response_data = b""
                while True:
                    part = s.recv(4096)
                    if not part: break
                    response_data += part
                s.close()

                if response_data:
                    response = json.loads(response_data.decode())
                    if response.get('status') == 'OK' and response.get('mode') == 'tables':
                        tables = response.get('tables', [])
                        aggregated[peer_id] = tables
                        print(f" -> Remote {peer_id}: {len(tables)} table(s)")

            except Exception:
                print(f" -> {peer_id}: unresponsive")

        # 3. Summarize
        total = sum(len(t) for t in aggregated.values())
        print(f"\n[RESULT] Total tables found across network: {total}")
        for pid, tables in aggregated.items():
            if tables:
                print(f"\nFrom {pid}:")
                for t in tables:
                    print(f"  - {t}")

        return aggregated

# ==============================================================
# COMMAND-LINE INTERFACE
# ==============================================================

def main():
    discovery_ip = input("Discovery Server IP (Default: 127.0.0.1): ")
    if not discovery_ip: discovery_ip = "127.0.0.1"
    discovery_port = 5000 

    my_id = input("Peer ID (e.g., Alice): ")
    my_port_input = input("Peer Port (e.g., 6001): ")
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
        print("3. View Local Data")
        print("4. Search Keyword (Local SSE)")
        print("5. Distributed Search (All Peers)")
        print("6. Distributed Key->Tables Search")
        print("7. Exit")
        choice = input("Choose: ")
        
        if choice == '1':
            peers = node.get_peers()
            print("Online Peers:", list(peers.keys()))
            
        elif choice == '2':
            peers = node.get_peers()
            if not peers:
                print("No peers found.")
                continue
            
            print("Available peers:", list(peers.keys()))
            targets_input = input("Recipients (comma separated): ")
            target_list = [t.strip() for t in targets_input.split(',') if t.strip()]
            
            if not target_list:
                print("Recipient list is empty.")
                continue

            table_name = input("Table name: ").strip()
            key = input("Key (k): ").strip()
            value = input("Value (v): ")

            save_local = input("Save local copy? (y/n): ").strip().lower()
            store_locally = (save_local == 'y')

            node.broadcast_data(value, target_list, table_name=table_name, key=key, store_locally=store_locally)
                
        elif choice == '3': # View Local Data
            try:
                table = input("Table name: ").strip()
                key = input("Key (k): ").strip()

                table_data = node.db.get_table(table)
                if not table_data:
                    print("Table not found or empty.")
                    continue

                matched_doc = None
                for doc_id, item in table_data.items():
                    if item.get('key') == key:
                        matched_doc = (doc_id, item)
                        break

                if not matched_doc:
                    print("Document not found.")
                    continue

                doc_id, item = matched_doc
                keys_map = item['encrypted_keys']
                
                if node.my_id in keys_map:
                    # Decrypt content
                    my_enc_key = keys_map[node.my_id]
                    sym_key = decrypt_rsa(node.private_key, my_enc_key)
                    plaintext = decrypt_data(sym_key, item['encrypted_data'].encode('utf-8'))
                    print(f"Key: {key} | Doc ID: {doc_id} | Content: {plaintext}")
                else:
                    print(f"Key: {key} | Doc ID: {doc_id} | [ACCESS DENIED] (Encrypted file)")
                
            except Exception as e:
                print(f"Error reading: {e}")

        elif choice == '4': # Search Local
            table_name = input("Table name: ").strip()
            keyword = input("Search keyword: ").strip()
            if not table_name or not keyword:
                print("Invalid input.")
                continue
            node.search_keyword(keyword, table_name)

        elif choice == '5': # Distributed Search
            table_name = input("Table name: ").strip()
            keyword = input("Search keyword: ").strip()
            if not table_name or not keyword:
                print("Invalid input.")
                continue
            node.search_distributed(keyword, table_name)
            
        elif choice == '6': # Distributed Tables Search
            key = input("Key (k) to search across tables: ").strip()
            if not key:
                print("Invalid input.")
                continue
            node.search_key_tables_distributed(key)

        elif choice == '7': # Exit
            print("Shutting down...")
            sys.exit()

if __name__ == "__main__":
    main()