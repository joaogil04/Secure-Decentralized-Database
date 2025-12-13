"""
database.py


This file implements a very simple local storage layer for each peer.

Each peer keeps its own local database in a JSON file on disk. The database stores 
encrypted data (in a key-value format) received from the network, as well as data created locally.

There is no shared storage and no remote access to this database: all read
(GET) operations are local.
"""

import json
import os

class LocalDatabase:
    """
    Represents a local key-value database stored in a JSON file.

    Each peer has its own instance of this class and its own storage file.
    The database is persistent across executions and automatically saved
    after each update.
    """
    def __init__(self, peer_id, folder="peer_data"):
        """
        Initializes the local database for a specific peer.

        - param peer_id: Identifier of the peer (used to name the storage file)
        - param folder: Directory where database files are stored

        NOTA: Separa dados de código criando uma pasta 'peer_data'.
        """
        self.folder = folder

        # File name is unique per peer
        self.filename = f"storage_{peer_id}.json"
        self.filepath = os.path.join(self.folder, self.filename)
        self.data = {}
        
        # Ensure storage directory exists and load existing data
        self._ensure_folder_exists()
        self.load()

    def _ensure_folder_exists(self):
        """
        Creates the storage directory if it does not already exist.
        This keeps database files separate from source code.
        """
        if not os.path.exists(self.folder):
            try:
                os.makedirs(self.folder)
            except OSError as e:
                print(f"[DB] Failed to create folder: {e}")

    def load(self):
        """
        Loads the database contents from disk into memory.

        If the file does not exist or is corrupted, an empty database
        is initialized.
        """

        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, 'r') as f:
                    self.data = json.load(f)
            except json.JSONDecodeError:
                # Corrupted or invalid JSON
                self.data = {}
        else:
            # No previous data found
            self.data = {}

    def save(self):
        """
        Persists the current in-memory database to disk.
        The file is overwritten on each save for consistency.
        """

        try:
            with open(self.filepath, 'w') as f:
                json.dump(self.data, f, indent=4)
        except Exception as e:
            print(f"[DB] Failed to save database: {e}")

    def put(self, key, value):
        """
        Stores a value under a given key and immediately saves it to disk.

        - param key: Key under which the value is stored
        - param value: Encrypted data to store
        """

        self.data[key] = value
        self.save()

    def get(self, key):
        """
        Retrieves the value associated with a given key.

        - param key: Key to retrieve
        - return: Stored value or None if the key does not exist
        """
        return self.data.get(key)
    