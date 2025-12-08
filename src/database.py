import json
import os

class LocalDatabase:
    def __init__(self, peer_id, folder="peer_data"):
        """
        Inicializa a base de dados numa pasta específica.
        :param peer_id: O nome do peer (ex: 'Alice') para dar nome ao ficheiro.
        :param folder: O nome da pasta onde guardar os dados.
        """
        self.folder = folder
        self.filename = f"storage_{peer_id}.json"
        
        # Cria o caminho completo: ./peer_data/storage_Alice.json
        # O os.path.join garante que funciona em Windows (\) e Linux (/)
        self.filepath = os.path.join(self.folder, self.filename)
        
        self.data = {}
        
        # Passo Crítico: Criar a pasta se ela não existir
        self._ensure_folder_exists()
        
        self.load()

    def _ensure_folder_exists(self):
        """Cria a pasta de dados se ainda não existir."""
        if not os.path.exists(self.folder):
            try:
                os.makedirs(self.folder)
                print(f"[DB] Pasta '{self.folder}' criada com sucesso.")
            except OSError as e:
                print(f"[DB] Erro ao criar pasta: {e}")

    def load(self):
        """Carrega a base de dados do caminho específico."""
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, 'r') as f:
                    self.data = json.load(f)
            except json.JSONDecodeError:
                self.data = {}
        else:
            self.data = {}

    def save(self):
        """Guarda os dados no ficheiro dentro da pasta."""
        try:
            with open(self.filepath, 'w') as f:
                json.dump(self.data, f, indent=4)
        except Exception as e:
            print(f"[DB] Erro ao guardar base de dados: {e}")

    def put(self, key, value):
        self.data[key] = value
        self.save()

    def get(self, key):
        return self.data.get(key)