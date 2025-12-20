# Secure Decentralized Database System

This project implements a secure distributed Peer-to-Peer (P2P) database system, developed for the **Data Privacy and Security (DPS)** course.

The system allows multiple clients (peers) to store and retrieve data securely, ensuring confidentiality, integrity, authenticity, and non-repudiation through hybrid cryptographic schemes. Additionally, it implements advanced features for identity protection and privacy-preserving search.
## Features

* **P2P Architecture:** Direct communication between peers for data storage and retrieval.

* **Discovery Server:** Directory service with a Heartbeat mechanism for real-time availability monitoring.

* **Robust Security (Hybrid Encryption):**

    * **Confidentiality:** Data is encrypted using AES-128 (Fernet).

    * **Secure Sharing (Multi-Recipient):** Symmetric keys are generated per message and encapsulated via RSA-OAEP (Digital Envelope) for multiple simultaneous recipients.

    * **Integrity and Authenticity:** Digital signatures using RSA-PSS on all transmissions.

* **Identity Protection:** Private keys are protected using Shamir's Secret Sharing (SSS), requiring both a disk file and a user password to reconstruct the identity.

* **Searchable Symmetric Encryption (SSE):** Supports privacy-preserving keyword search (Local and Distributed) using deterministic trapdoors and inverted indexes.

* **Local Persistence:** Each peer maintains its local state in isolated and protected JSON files (Data at Rest).

* **Interactive Interface:** CLI menu to list peers, broadcast secure data, view local data, and perform distributed searches.

## Prerequisites

* **Python 3.8+**

* **Cryptography Library:** Used for all cryptographic primitives (AES, RSA, HMAC, HKDF).

### Installation

Install the required dependencies from the project root:

    pip install cryptography

## How to Run

To test the system, it is recommended to use 3 different terminals (1 for Discovery and 2 for Peers). Ensure you are in the project root directory.
1. **Start the Discovery Server (Terminal 1)**

This server must be started first. It manages the list of active nodes and distributes public keys.

    python src/discovery_server.py

The server will listen on port 5000.
2. **Start Peer "Alice" (Terminal 2)**

    python src/peer_node.py

Provide the following inputs when prompted:

* **Discovery IP:** 127.0.0.1 (or Enter for default)

* **Peer ID:** Alice

* **Peer Port:** 6001

* **Password:** Enter a password to protect/unlock the local identity vault (SSS).

3. **Start Peer "Bob" (Terminal 3)**

    python src/peer_node.py

Provide the following inputs when prompted:

* **Discovery IP:** 127.0.0.1 (or Enter for default)

* **Peer ID:** Bob

* **Peer Port:** 6002 (Important: Must be different from Alice's port)

* **Password:** Enter a password for Bob's vault.

---

## Security Architecture

This project follows the **"Encrypt-then-Sign"** paradigm and utilizes **Hybrid Encryption (Digital Envelope)** alongside **Searchable Encryption** protocols.

**1. Identity Management (Shamir's Secret Sharing)**

Peers do not store their RSA Private Keys in plaintext. Instead, the identity is protected using a 2-of-2 Shamir's Secret Sharing scheme:

* **Share 1 (Possession):** Stored as a file on the disk (share_disk.dat).

* **Share 2 (Knowledge):** Encrypted with a key derived from the user's password (share_pass.dat). Both shares are required to reconstruct the Master Key in memory, which then decrypts the RSA Private Key.

**2. Confidentiality (AES + RSA)**

When sending a file to the network (e.g., Alice to Bob and Charlie):

   1. A random, unique **Symmetric Key (AES-128)** is generated for the message.

   2. The data is encrypted with this key (using Fernet, which includes HMAC for integrity).

   3. The symmetric key is encrypted repeatedly with the **Public Key of each recipient** (RSA-OAEP).

   4. Only recipients with the corresponding Private Key can decrypt the symmetric key to read the data.

**3. Integrity and Authenticity (Digital Signatures)**

To ensure data origin and prevent tampering:

   1. The sender calculates the SHA-256 hash of the encrypted data.

   2. The sender signs this hash with their **Private Key** (RSA-PSS).

   3. Receivers verify the signature using the sender's **Public Key**. If validation fails, the data is rejected.

**4. Searchable Symmetric Encryption (SSE)**

The system allows searching for encrypted data without decrypting it:

* **Trapdoors:** Keywords are hashed using HMAC and a secure search key derived via HKDF. These deterministic hashes (trapdoors) are sent to the network instead of plaintext keywords.

* **Inverted Index:** Peers maintain a local index mapping trapdoors to document IDs.

* **Privacy:** The server (peer) can identify which documents contain a keyword matching the trapdoor but cannot determine the actual keyword itself.

## Project Structure

    /Project_PSD
    │
    ├── keys/                   # Local key storage (SSS shares and encrypted identity)
    │   ├── identity.enc
    │   ├── share_disk.dat
    │   └── share_pass.dat
    │
    ├── peer_data/              # Persistent encrypted data (JSON files separated by Peer)
    │   ├── storage_Alice.json
    │   └── storage_Bob.json
    │
    └── src/                    # Source Code
        ├── peer_node.py        # Main P2P Client/Server logic (PUT, SEARCH, Broadcast)
        ├── discovery_server.py # Directory and monitoring server (Heartbeat)
        ├── crypto_utils.py     # Cryptographic library (PyCA wrapper, SSS, SSE)
        └── database.py         # Local persistence and Inverted Index management

## Authors

* **João Gil** 
* **Francisco Pechirra**
* **Raquel Amaral**
