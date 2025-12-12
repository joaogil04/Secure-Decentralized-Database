# Secure Decentralized Database

[cite_start]Este projeto implementa um sistema de base de dados distribuída (Peer-to-Peer) segura, desenvolvido no âmbito da disciplina de **Data Privacy and Security (DPS)**[cite: 4969].

O sistema permite que múltiplos clientes (peers) armazenem e recuperem dados de forma segura, garantindo confidencialidade, integridade, autenticidade e não-repúdio através de esquemas criptográficos híbridos.

## Funcionalidades

* [cite_start]**Arquitetura P2P:** Comunicação direta entre pares para armazenamento de dados[cite: 4979].
* **Discovery Server:** Servidor de diretório com *Heartbeat* para monitorização de disponibilidade em tempo real.
* **Segurança Robusta (Hybrid Encryption):**
    * **Confidencialidade:** Dados encriptados com AES-128 (Fernet).
    * **Partilha Segura:** Chaves simétricas geradas por ficheiro e encapsuladas via RSA-OAEP (Envelope Digital).
    * [cite_start]**Integridade e Autenticidade:** Assinaturas digitais RSA-PSS em todos os envios[cite: 909].
* **Persistência Local:** Cada peer mantém o seu estado local em ficheiros JSON isolados e protegidos.
* **Interface Interativa:** Menu CLI para listar peers, enviar dados e desencriptar armazenamento local.

## Pré-requisitos

* **Python 3.8+**
* **Biblioteca Cryptography:** Utilizada para todas as primitivas criptográficas (AES, RSA, HMAC).

### Instalação

Na raiz do projeto, instala as dependências necessárias:

    pip install cryptography

## Como Executar

Para testar o sistema, recomenda-se a utilização de **3 terminais diferentes** (1 para o Discovery e 2 para Peers). Certifica-te que estás na pasta raiz do projeto.

### 1. Iniciar o Discovery Server (Terminal 1)
Este servidor deve ser o primeiro a arrancar. Ele gere a lista de nós ativos e distribui as chaves públicas.

    python src/discovery_server.py

> O servidor ficará à escuta na porta 5000.

### 2. Iniciar o Peer "Alice" (Terminal 2)

    python src/peer_node.py

Serve os seguintes inputs quando solicitado:
* **IP Discovery:** 127.0.0.1 (ou Enter para default)
* **ID:** Alice
* **Porta:** 6001

### 3. Iniciar o Peer "Bob" (Terminal 3)

    python src/peer_node.py

Serve os seguintes inputs quando solicitado:
* **IP Discovery:** 127.0.0.1 (ou Enter para default)
* **ID:** Bob
* **Porta:** 6002 (Importante: Tem de ser uma porta diferente da Alice!)

---

## Arquitetura de Segurança

[cite_start]Este projeto segue o paradigma **"Encrypt-then-Sign"** [cite: 800] e utiliza **Encriptação Híbrida (Digital Envelope)** para maximizar a segurança e performance.

### 1. Identidade (RSA)
[cite_start]No arranque, cada Peer gera um par de chaves RSA 2048-bit[cite: 890].
* **Chave Privada:** Nunca sai do armazenamento local do Peer (memória/disco).
* **Chave Pública:** É enviada para o Discovery Server no registo e distribuída aos outros Peers para validação de assinaturas e encriptação de chaves.

### 2. Confidencialidade (AES + RSA)
Quando a Alice envia um ficheiro para o Bob:
1.  Gera-se uma **Chave Simétrica (AES-128)** aleatória e única para aquele envio.
2.  Os dados são encriptados com essa chave (usando *Fernet*, que inclui HMAC para integridade).
3.  A chave simétrica é encriptada com a **Chave Pública do Bob** (RSA-OAEP).
4.  O Bob recebe o "Envelope Digital" e só ele consegue abrir a chave com a sua Chave Privada para ler os dados.

### 3. Integridade e Autenticidade (Assinaturas Digitais)
Para garantir que os dados não foram alterados e vieram mesmo da Alice:
1.  A Alice calcula o Hash (SHA-256) dos dados encriptados.
2.  A Alice assina esse hash com a sua **Chave Privada** (RSA-PSS).
3.  O Bob, ao receber, valida a assinatura usando a **Chave Pública da Alice** (obtida via Discovery). [cite_start]Se a validação falhar, os dados são rejeitados imediatamente[cite: 909].

## Estrutura do Projeto

    /Project_PSD
    │
    ├── keys/                   # Armazenamento local de chaves (criada automaticamente)
    ├── peer_data/              # Dados encriptados persistentes (JSON separados por Peer)
    │   ├── storage_Alice.json
    │   └── storage_Bob.json
    │
    └── src/                    # Código Fonte
        ├── peer_node.py        # Lógica principal do Cliente/Servidor P2P
        ├── discovery_server.py # Servidor de diretório e monitorização (Heartbeat)
        ├── crypto_utils.py     # Biblioteca de funções criptográficas (PyCA wrapper)
        └── database.py         # Gestão de persistência local

## Notas para Avaliação

* **Bibliotecas:** Foi utilizada a `cryptography.io`, recomendada pela indústria por evitar vulnerabilidades comuns em implementações manuais de algoritmos matemáticos ("Don't roll your own crypto").
* **Dinamicidade:** O sistema suporta a entrada e saída dinâmica de nós (Dynamic Join/Leave) graças ao sistema de Heartbeat do Discovery Server.
* **Data at Rest:** A base de dados armazena apenas BLOBs encriptados e as chaves encriptadas. Mesmo que o ficheiro JSON seja roubado, o atacante não consegue ler o conteúdo sem a chave privada do utilizador.

## Autores

* **João Maria** - *Aluno FCUL*