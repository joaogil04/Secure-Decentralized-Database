"""
database.py

This file implements the local storage layer for each peer.

Each peer maintains its own local database using a persistent JSON file. 
The database stores:
1. Encrypted Data: Key-value pairs organized by tables.
2. Search Index: An Inverted Index structure to support Searchable Symmetric Encryption (SSE).

There is no shared storage and no remote access to this database file directly; 
all network operations interact with the PeerNode logic, which then calls this class.
"""

import json
import os

class LocalDatabase:
    """
    Represents a local key-value database stored in a JSON file.

    Each peer has its own instance of this class and its own storage file.
    The database is persistent across executions (Data at Rest) and automatically 
    saved after each update to ensure durability.
    """

    def __init__(self, peer_id, folder="peer_data"):
        """
        Initializes the local database for a specific peer.

        - param peer_id: Identifier of the peer (used to name the storage file).
        - param folder: Directory where database files are stored.
        
        NOTE: Separates data from source code by creating a dedicated 'peer_data' folder.
        """
        self.folder = folder
        self.filename = f"storage_{peer_id}.json"  # Unique filename per peer
        self.filepath = os.path.join(self.folder, self.filename)
        self.data = {}  # Structure: { "TableName": { doc_id: value, ... }, "search_index": ... }
        
        # Ensure storage directory exists and load existing data
        self._ensure_folder_exists()
        self.load()

    def _ensure_folder_exists(self):
        """
        Creates the storage directory if it does not already exist.
        """
        if not os.path.exists(self.folder):
            try:
                os.makedirs(self.folder)
            except OSError as e:
                print(f"[DB] Failed to create folder: {e}")

    def load(self):
        """
        Loads the database contents from disk into memory.

        If the file does not exist or is corrupted (JSONDecodeError), 
        an empty database is initialized to prevent crashes.
        """
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, 'r') as f:
                    self.data = json.load(f)
            except json.JSONDecodeError:
                # Handle corrupted JSON gracefully
                print(f"[DB] Warning: Corrupted database file found. Starting with empty DB.")
                self.data = {}
        else:
            # No previous data found
            self.data = {}

    def save(self):
        """
        Persists the current in-memory database to disk.
        
        The file is overwritten on each save to ensure consistency between 
        memory and disk states.
        """
        try:
            with open(self.filepath, 'w') as f:
                json.dump(self.data, f, indent=4)
        except Exception as e:
            print(f"[DB] Failed to save database: {e}")

    def put(self, doc_id, value, table):
        """
        Stores a document in a given table using its internal doc_id.
        Creates the table if it doesn't exist.

        - param doc_id: Internal unique document ID.
        - param value: Dictionary containing the encrypted payload and metadata.
        - param table: Name of the table (category).
        """
        if table not in self.data:
            self.data[table] = {}
        
        self.data[table][doc_id] = value
        self.save()
    
    def get_table(self, table):
        """
        Retrieves an entire table as a dictionary.
        Returns an empty dict if the table does not exist.
        """
        return self.data.get(table, {})
    
    # ==============================================================
    # SEARCHABLE SYMMETRIC ENCRYPTION (SSE) INDEX METHODS
    # ==============================================================

    def put_search_index(self, table, trapdoor, doc_id):
        """
        Updates the Inverted Index for SSE.
        
        This method links a 'trapdoor' (deterministic hash of a keyword) to a document ID.
        This structure allows efficient lookups (O(1) dictionary access) to find which 
        documents contain a specific keyword without scanning the entire database.
        
        - param table: Table name.
        - param trapdoor: The secure search token (base64 string).
        - param doc_id: The document ID that contains the keyword.
        """
        if "search_index" not in self.data:
            self.data["search_index"] = {}
        
        if table not in self.data["search_index"]:
            self.data["search_index"][table] = {}
        
        if trapdoor not in self.data["search_index"][table]:
            self.data["search_index"][table][trapdoor] = []
        
        # Avoid duplicates in the index
        if doc_id not in self.data["search_index"][table][trapdoor]:
            self.data["search_index"][table][trapdoor].append(doc_id)
        
        self.save()

    def search_by_trapdoor(self, table, trapdoor):
        """
        Searches for all documents matching a trapdoor within a specific table.
        
        This utilizes the Inverted Index to perform a privacy-preserving search.
        The database never sees the plaintext keyword, only the trapdoor.
        
        - param table: Table name to search in.
        - param trapdoor: The search trapdoor.
        - return: List of matching document IDs.
        """
        if "search_index" not in self.data:
            return []
        
        index = self.data.get("search_index", {})
        table_index = index.get(table, {})
        
        return table_index.get(trapdoor, [])

    def search_by_key(self, key):
        """
        Searches for all tables where a specific user-defined 'key' appears.
        
        This performs a metadata search (not content search) across all tables,
        skipping the internal 'search_index' table.
        
        - param key: The user-provided key (e.g., filename) to search for.
        - return: List of table names where the key exists.
        """
        tables_with_key = []
        
        for table_name, table_data in self.data.items():
            # Skip the reserved SSE index table
            if table_name == "search_index":
                continue
            
            # Check each document in the table
            for doc_id, item in table_data.items():
                if isinstance(item, dict) and item.get('key') == key:
                    if table_name not in tables_with_key:
                        tables_with_key.append(table_name)
                    break
        
        return tables_with_key
    
    def search_tables_by_trapdoor(self, trapdoor):
        """
        Identifies which tables contain a specific trapdoor.
        
        This allows for distributed searching across multiple tables without 
        knowing the table name beforehand.
        
        - param trapdoor: The search token.
        - return: List of table names containing the trapdoor.
        """
        found_tables = []
        if "search_index" not in self.data:
            return []

        search_index = self.data["search_index"]
        
        # Iterate over all tables in the index to find the trapdoor
        for table_name, traps in search_index.items():
            if trapdoor in traps:
                found_tables.append(table_name)
        
        return found_tables