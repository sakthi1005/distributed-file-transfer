## Distributed File Transfer System

A fault-tolerant, multi-source file transfer system that transfers files across multiple computers on a LAN using Python.

### Key Features

- UDP Discovery: Automatically discovers multiple senders.
- Parallel Transfer: Downloads different file chunks from multiple senders using TCP.
- Dynamic Scheduling: Assigns more chunks to faster senders.
- Fault Tolerance: Recovers from corrupted chunks and sender failures.
- Endgame Mode: Duplicates remaining chunks to reduce waiting time.
- Integrity Verification: Uses CRC-32 and SHA-256 to verify file accuracy.
- Resume Support: Continues interrupted transfers without restarting.
- Security: Supports HMAC authentication and optional TLS encryption.
- Smart Scheduling: Uses Thompson Sampling and SPRT to improve efficiency.

### Architecture

1. Receiver: Discovers senders and manages downloads.
2. Senders: Provide file chunks through TCP.
3. Scheduler: Assigns chunks and handles failures.
4. Verifier: Checks chunk and file integrity.
5. State Manager: Saves progress for resuming transfers.

### Technologies Used

- Python 3.9+
- UDP and TCP sockets
- Multithreading
- HMAC, CRC-32 and SHA-256
- TLS/SSL
- JSON

### Expected Outcome

A reliable file transfer system that downloads files from multiple computers simultaneously, detects corrupted data, handles sender failures, and verifies the completed file.

Advantage: Unlike traditional file transfer systems, it supports parallel downloads, automatic failover, intelligent scheduling, and interrupted-transfer recovery using only Python's standard library.
