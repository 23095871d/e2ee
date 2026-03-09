# COMP3334 Secure Instant Messenger (E2EE)

A secure instant messaging application with **end-to-end encryption (E2EE)** for 1:1 private chats. Built as part of the COMP3334 Computer Systems Security course project.

## Features

- **End-to-End Encrypted Messaging**: All messages are encrypted on the sender's device and can only be decrypted by the intended recipient. The server never sees plaintext.
- **Two-Factor Authentication**: Login requires both a password and a TOTP (Time-based One-Time Password) code.
- **Timed Self-Destruct Messages**: Messages can be set to automatically delete after a configurable time duration.
- **Friend Request System**: Add contacts via a request/accept/decline workflow.
- **Offline Messaging**: Messages sent while the recipient is offline are stored (encrypted) and delivered when they come back online.
- **Message Delivery Status**: Track whether messages have been sent and delivered.
- **Fingerprint Verification**: Verify contacts' identity keys to prevent MITM attacks.
- **Key Change Detection**: Warnings when a contact's identity key changes.
- **TLS Transport Security**: All client-server communication uses HTTPS/WSS.
- **Rate Limiting**: Protection against brute-force login attempts and spam.

## Technology Stack

| Component | Technology |
|---|---|
| Language | Python 3.10+ |
| Server | Flask + Flask-SocketIO (WebSocket) |
| Database | SQLite (local, both server and client) |
| Key Exchange | X25519 (Elliptic Curve Diffie-Hellman) |
| Signatures | Ed25519 |
| Encryption | AES-256-GCM (AEAD) |
| Key Derivation | HKDF-SHA256 |
| Password Hashing | Argon2id |
| 2FA | TOTP (RFC 6238) |
| Transport | TLS 1.2+ (self-signed certificates) |
| Crypto Library | Python `cryptography` v44.0.0 |

## Prerequisites

- **Python 3.10 or higher** (download from https://www.python.org/downloads/)
- **pip** (comes with Python)

## Deployment Guide (Step-by-Step)

### Step 1: Install Python

**Windows 11:**
1. Download Python 3.10+ from https://www.python.org/downloads/
2. Run the installer
3. **IMPORTANT**: Check "Add Python to PATH" during installation
4. Verify: Open Command Prompt and run `python --version`

**Ubuntu Linux:**
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv
```

### Step 2: Set Up the Project

1. Open a terminal/command prompt
2. Navigate to the project directory:

```bash
cd path/to/comp3334project2
```

3. (Recommended) Create a virtual environment:

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux
python3 -m venv venv
source venv/bin/activate
```

4. Install dependencies:

```bash
pip install -r requirements.txt
```

### Step 3: Generate TLS Certificates

The server uses TLS (HTTPS) for secure communication. Generate self-signed certificates:

```bash
python generate_certs.py
```

This creates:
- `certs/ca_cert.pem` - CA certificate (for client verification)
- `certs/ca_key.pem` - CA private key
- `certs/server_cert.pem` - Server certificate
- `certs/server_key.pem` - Server private key

### Step 4: Initialize the Server Database

The database is automatically initialized when the server starts. You can also manually import the schema:

```bash
# Optional: manually create the database
sqlite3 server/server.db < setup_database.sql
```

### Step 5: Start the Server

```bash
python run_server.py
```

The server will start on `https://localhost:5000` with TLS enabled.

### Step 6: Open the Web UI in Your Browser

Open your web browser and navigate to:

```
https://localhost:5000
```

**Note:** Your browser will show a certificate warning because we use a self-signed certificate. This is expected -- click "Advanced" and "Proceed to localhost" to continue.

You can also open multiple browser tabs/windows to simulate different users chatting with each other.

### Alternative: CLI Client

If you prefer a command-line interface, you can also use the CLI client:

```bash
python run_client.py
```

## How to Use (Web UI)

### Registration

1. Open `https://localhost:5000` in your browser
2. Click "Register" on the login page
3. Enter a username (3-32 alphanumeric characters)
4. Enter a password (minimum 8 chars, at least 1 uppercase letter, 1 digit)
5. The system will show your TOTP secret for two-factor authentication
6. **Save the TOTP secret!** You need it to log in.
   - Add it to an authenticator app (Google Authenticator, Authy, etc.)
   - The secret is also saved in your browser's localStorage for testing convenience

### Login

1. Enter your username and password
2. Enter the 6-digit OTP code from your authenticator app
   - If you leave the OTP field empty, the client auto-generates one from the stored secret (for testing convenience)
3. Click "Login"

### Adding Friends

1. Click the **"+ Add Friend"** button in the sidebar
2. Enter the username you want to add
3. Click **"Send Request"**

### Managing Friend Requests

1. Click the **"Requests"** button in the sidebar
2. View received and sent requests
3. Click **Accept** or **Decline** on received requests

### Chatting

1. Click on a friend in the sidebar to open the chat
2. Type your message and press **Enter** or click **Send**
3. Messages are end-to-end encrypted automatically

### Self-Destruct Messages

1. In a chat, click the timer icon (top-right corner)
2. Select a duration (30s, 1min, 5min, 10min)
3. Messages sent with TTL will auto-delete after the timer expires

### Verifying Contacts

1. In a chat, click the key icon (top-right corner)
2. Compare the fingerprint with your contact out-of-band
3. Click **"Mark as Verified"** if the numbers match

## Testing with Two Users

**Step 1:** Start the server:
```bash
python run_server.py
```

**Step 2:** Open two browser tabs (or windows) to `https://localhost:5000`

**Step 3:** In Tab 1, register as "alice" and login.

**Step 4:** In Tab 2, register as "bob" and login.

**Step 5:** In Tab 1 (Alice): Click "+ Add Friend", type "bob", send request.

**Step 6:** In Tab 2 (Bob): Click "Requests", accept Alice's request.

**Step 7:** Both tabs: Click on the friend in the sidebar and start chatting!

All messages are end-to-end encrypted -- the server only sees ciphertext.

## Security Architecture

### Threat Model
- **Server (Honest-but-Curious)**: Follows the protocol but may inspect all data
- **Network Attacker**: May observe traffic; TLS prevents MITM
- **Malicious Users**: Rate limiting and input validation prevent abuse

### E2EE Protocol
1. Each user generates X25519 (key exchange) and Ed25519 (signing) keypairs
2. Session establishment uses a simplified X3DH-like protocol
3. Messages encrypted with AES-256-GCM (authenticated encryption)
4. Replay protection via message counters
5. Fingerprints allow out-of-band verification

### What the Server Can See (Metadata)
- Who is talking to whom (contact graph)
- When messages are sent (timestamps)
- Message sizes
- Online/offline status

### What the Server Cannot See
- Message contents (encrypted with E2EE)
- Private keys (never leave the client)
- Plaintext passwords (only Argon2id hashes are stored)

## Project Structure

```
comp3334project2/
├── server/
│   ├── __init__.py
│   ├── app.py              # Server application (Flask + SocketIO)
│   ├── database.py         # Server database operations
│   ├── templates/
│   │   └── index.html      # Web UI (single-page application)
│   └── static/
│       ├── css/
│       │   └── style.css   # Web UI styling
│       └── js/
│           ├── crypto.js   # Browser-side E2EE crypto (X25519, AES-GCM, HKDF)
│           └── app.js      # Web application logic
├── client/
│   ├── __init__.py
│   ├── main.py             # CLI client (alternative to web UI)
│   ├── crypto_utils.py     # Python cryptographic operations
│   ├── local_db.py         # Client local database
│   └── network.py          # Server communication (HTTP + WebSocket)
├── certs/                  # TLS certificates (generated)
├── data/                   # Local user data (generated at runtime)
├── generate_certs.py       # TLS certificate generator
├── setup_database.sql      # Server database schema (importable)
├── run_server.py           # Server entry point
├── run_client.py           # CLI client entry point
├── requirements.txt        # Python dependencies
└── README.md               # This file
```

## Cryptographic Libraries Used

| Library | Version | Purpose |
|---|---|---|
| `cryptography` | 44.0.0 | X25519, Ed25519, AES-256-GCM, HKDF-SHA256 |
| `argon2-cffi` | 23.1.0 | Password hashing (Argon2id) |
| `pyotp` | 2.9.0 | TOTP generation and verification |

## Known Limitations

1. **No Double Ratchet**: The current protocol uses a simple symmetric ratchet. Compromising the session key reveals future messages (but not past ones).
2. **No Group Chat**: Only 1:1 messaging is supported.
3. **No Multi-Device Sync**: Each device has its own identity keys.
4. **Self-Destruct Limitations**: Cannot prevent screenshots or copy/paste by a malicious client.
5. **Self-Signed Certificates**: In production, use certificates from a real CA.
