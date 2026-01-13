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
## 🔁 QR Auth flow (sequence diagram)

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser (User)
    participant W as Web Server (FastAPI)
    participant S as Session Store (in-memory)
    participant Q as QR (dna:// payload)
    participant M as DNA-Messenger (Phone)
    participant V as Native Verifier (PQClean ML-DSA-87)

    B->>W: GET /
    W->>S: create_session(origin, ttl)
    S-->>W: session_id, challenge, issued_at, expires_at
    W-->>B: landing.html (contains session_id + QR URL)

    B->>W: GET /api/v1/session/{sid}/qr.svg
    W->>S: get(sid)
    S-->>W: sess.qr_uri
    W->>Q: render QR from sess.qr_uri
    W-->>B: qr.svg

    Note over B,M: User scans QR on the phone

    M->>W: (optional) GET /api/v1/session/{sid}/challenge
    W->>S: get(sid)
    S-->>W: challenge + metadata
    W-->>M: challenge payload

    M->>M: Build canonical JSON string
    Note over M: canonical = {"expires_at":...,"issued_at":...,"nonce":"...","origin":"...","session_id":"..."}
    M->>M: signature = ML-DSA-87 sign(canonical_bytes)
    M->>M: pubkey_b64 + fingerprint = SHA3-512(pubkey).hex

    M->>W: POST /api/v1/session/{sid}/complete<br/>{"type":"dna.auth.response","v":1,...}
    W->>S: get(sid) + validate pending/ttl
    W->>W: Validate fields + origin/session_id + nonce replay
    W->>W: Compute fingerprint = SHA3-512(pubkey).hex
    W->>W: Compare claimed_fp == computed_fp (fail-closed)
    W->>V: verify_mldsa87_signature(pubkey, canonical_bytes, signature)
    V-->>W: ok / fail

    alt signature valid
        W->>S: save_response(... verified=true ...)
        W->>S: set_status(APPROVED)
        W-->>M: 200 {"ok": true}
    else signature invalid
        W->>S: set_status(DENIED)
        W-->>M: 403 invalid signature
    end

    loop Browser polling
        B->>W: GET /api/v1/session/{sid}
        W->>S: get(sid)
        S-->>W: status (pending/approved/denied/expired)
        W-->>B: status JSON
    end

    alt approved
        B->>W: GET /success
        W-->>B: success.html
    else denied/expired
        W-->>B: show failed state
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

