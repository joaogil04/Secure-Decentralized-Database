import json
import os

class LocalDatabase:
    def __init__(self, peer_id, folder="peer_data"):
        """
        Gere o armazenamento local num ficheiro JSON.
        Separa dados de código criando uma pasta 'peer_data'.
        """
        self.folder = folder
        self.filename = f"storage_{peer_id}.json"
        self.filepath = os.path.join(self.folder, self.filename)
        self.data = {}
        
        self._ensure_folder_exists()
        self.load()

    def _ensure_folder_exists(self):
        if not os.path.exists(self.folder):
            try:
                os.makedirs(self.folder)
            except OSError as e:
                print(f"[DB] Erro ao criar pasta: {e}")

    def load(self):
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, 'r') as f:
                    self.data = json.load(f)
            except json.JSONDecodeError:
                self.data = {}
        else:
            self.data = {}

    def save(self):
        try:
            with open(self.filepath, 'w') as f:
                json.dump(self.data, f, indent=4)
        except Exception as e:
            print(f"[DB] Erro ao guardar: {e}")

    def put(self, key, value):
        self.data[key] = value
        self.save()

    def get(self, key):
        return self.data.get(key)