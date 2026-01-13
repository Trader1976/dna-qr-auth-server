# DNA QR Auth Server

A QR-code–based authentication server for **DNA-Messenger**, implementing **device-mediated, post-quantum authentication** using native PQClean signature verification.

This service allows a website or application to authenticate a user by displaying a QR code.  
The QR code is scanned and approved in the DNA-Messenger mobile app, which **cryptographically proves the user’s identity**.  
The browser session is approved **without passwords, cookies, or shared secrets**.

---

## ✨ Features

- QR-based login / authorization flow
- Device-mediated approval via DNA-Messenger
- Stateless browser polling (no WebSockets required)
- Strict session lifecycle: `pending → approved / denied / expired`
- **Post-quantum signatures (ML-DSA-87 / Dilithium-class)**
- **Native PQClean signature verification (C, not Python crypto)**
- Fingerprint ↔ public key binding (SHA3-512)
- Replay protection via nonces
- Dockerized FastAPI backend
- Nginx reverse proxy support
- Works locally and via Cloudflare Tunnel

---

## 🧠 How it works (high level)
This server implements a device-mediated, post-quantum authentication flow using QR codes and native PQClean signature verification.

A browser session is authenticated only after a mobile device cryptographically approves it.
No passwords, cookies, or shared secrets are used.

sequenceDiagram
    autonumber

    participant B as Browser
    participant W as FastAPI Server
    participant S as Session Store
    participant M as DNA-Messenger (Phone)
    participant V as Native Verifier (PQClean)

    B->>W: GET /
    W->>S: create_session(origin, ttl)
    S-->>W: session_id, issued_at, expires_at
    W-->>B: landing.html (session_id + QR)

    B->>W: GET /api/v1/session/{sid}/qr.svg
    W->>S: get_session(sid)
    S-->>W: qr_uri
    W-->>B: SVG QR code

    Note over B,M: User scans QR code with phone

    M->>M: Parse QR payload
    M->>M: Build canonical JSON payload
    M->>M: Sign payload with ML-DSA-87
    M->>M: Compute fingerprint = SHA3-512(pubkey)

    M->>W: POST /api/v1/session/{sid}/complete
    W->>S: validate session state
    W->>W: validate origin, timestamps, nonce
    W->>W: fingerprint == SHA3-512(pubkey)
    W->>V: verify signature (native PQClean)
    V-->>W: verification result

    alt signature valid
        W->>S: set_status(APPROVED)
        W-->>M: 200 OK
    else invalid
        W->>S: set_status(DENIED)
        W-->>M: 403 Forbidden
    end

    loop Browser polling
        B->>W: GET /api/v1/session/{sid}
        W->>S: get_status
        S-->>W: status
        W-->>B: status JSON
    end

    alt approved
        B->>W: GET /success
        W-->>B: success.html
    else denied or expired
        W-->>B: failure state
    end



1. **Browser opens login page**
   - Server creates a short-lived authentication session
   - A QR code is rendered containing a challenge descriptor

2. **User scans QR code with DNA-Messenger**
   - App validates payload (origin, expiry, callback)
   - User approves or denies the request
   - App builds a **canonical payload**
   - App signs the payload using the user’s DNA identity (ML-DSA-87)
   - App POSTs signature, public key, and fingerprint to the server

3. **Server verifies cryptographically**
   - Reconstructs the canonical payload
   - Verifies fingerprint ↔ public key binding
   - Verifies signature using **native PQClean (ML-DSA-87)**
   - Session is marked `approved` or `denied`

4. **Browser polls session status**
   - When approved, browser redirects to `/success`

This flow is conceptually similar to GitHub Device Login or WalletConnect, but uses **user-owned, post-quantum cryptographic identity** instead of OAuth or browser-anchored trust.

---

## 🔐 Cryptography (important)

- **Signature algorithm:** ML-DSA-87 (Dilithium-class, NIST PQC)
- **Verification:** Native C code via PQClean
- **Identity fingerprint:** `SHA3-512(public_key)` (128-hex chars)
- **No algorithm fallback**
- **No Python-level signature verification**
- **No shared secrets**

The server acts strictly as a verifier.  
Private keys **never leave the mobile device**.

---

## 🧱 Project structure
dna-qr-auth-server/
├── app/
│ ├── main.py # FastAPI routes + verification logic
│ ├── identity.py # Native PQClean verifier wrapper
│ ├── storage.py # In-memory session store
│ ├── config.py # Environment-based settings
│ ├── qr.py # QR code generation
│ ├── native/
│ │ ├── PQClean/ # PQClean source (vendored)
│ │ ├── dilithium_verify.c
│ │ └── libdna_pq_verify.so
│ ├── templates/
│ │ ├── landing.html
│ │ └── success.html
│ └── static/
│ ├── app.js # Browser polling + redirect logic
│ └── style.css # CPUNK-themed styles
├── nginx/
│ └── default.conf # Reverse proxy config
├── docker-compose.yml
├── Dockerfile
└── README.md

---

## 🚀 Run locally (Docker)

### Requirements
- Docker
- Docker Compose

### Start the server
```bash
docker compose up --build


Then open:
http://localhost:8081

⚙️ Configuration

Configuration is handled via environment variables (see config.py).

Key settings:

Variable	Description
ORIGIN	Public origin shown to the user
SESSION_TTL_SECONDS	Auth session lifetime
RP_ID	Relying Party identifier
RP_NAME	Display name shown in app
SCOPES	Requested permissions
You can override these via .env or docker-compose.yml.

🧪 Status

✅ QR auth flow working end-to-end
✅ Native post-quantum signature verification
✅ Browser redirect on approval
✅ Replay and expiry protection

🚧 Persistent storage (currently in-memory)
🚧 Formal protocol specification
🚧 Scope-binding enforcement

This project is experimental and under active development.

🔐 Security notes

No passwords are exchanged
No cookies are required for authentication
Sessions are short-lived and single-use
Nonces prevent replay attacks
Signature verification uses native PQClean code
Designed for post-quantum threat models
Do not deploy to production without a security review.

🧬 Related projects

DNA-Messenger — Post-quantum identity & messaging
CPUNK Protocol — Decentralized, quantum-safe stack

