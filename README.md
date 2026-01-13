# DNA QR Auth Server

A QR-code–based authentication server for **DNA-Messenger**, implementing **device-mediated, post-quantum authentication** using native **PQClean** signature verification.

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

This server implements a device-mediated, post-quantum authentication flow using QR codes and **native PQClean** signature verification.

A browser session is authenticated only after a mobile device cryptographically approves it.
No passwords, cookies, or shared secrets are used.

### Flowchart

```mermaid
flowchart TD
  A[Browser opens /] --> B[FastAPI creates session<br/>status=pending, ttl]
  B --> C[Browser loads /api/v1/session/{sid}/qr.svg]
  C --> D[Server renders QR containing dna://auth payload<br/>origin, session_id, nonce, expires_at, callback]
  D --> E[User scans QR with DNA-Messenger]
  E --> F[App parses payload + validates origin/expiry/callback]
  F --> G[App builds canonical JSON string]
  G --> H[App signs canonical bytes with ML-DSA-87<br/>(Dilithium-class)]
  H --> I[App computes fingerprint = SHA3-512(pubkey)]
  I --> J[POST /api/v1/session/{sid}/complete<br/>fingerprint, pubkey_b64, signature, signed_payload]
  J --> K[Server validates session state + timestamps + nonce]
  K --> L[Server checks fingerprint == SHA3-512(pubkey)]
  L --> M[Server verifies signature via native PQClean .so]
  M -->|valid| N[Set status=approved + save response]
  M -->|invalid| O[Set status=denied]
  N --> P[Browser polling sees approved]
  O --> Q[Browser polling sees denied/expired]
  P --> R[Browser redirects to /success]


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
  W-->>B: landing.html (session_id + polling JS)

  B->>W: GET /api/v1/session/{sid}/qr.svg
  W->>S: get_session(sid)
  S-->>W: qr_uri
  W-->>B: SVG QR code

  Note over B,M: User scans QR code with phone

  M->>M: Parse QR payload
  M->>M: Build canonical JSON string
  M->>M: Sign bytes with ML-DSA-87
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
    W-->>B: failure state (UI decides)
  end

🔐 Cryptography (important)

Signature algorithm: ML-DSA-87 (Dilithium-class, NIST PQC family)
Verification: native C code via PQClean (libdna_pq_verify.so)
Identity fingerprint: SHA3-512(public_key) (128 hex chars)
No algorithm fallback
No Python-level signature verification
No shared secrets
The server acts strictly as a verifier.
Private keys never leave the mobile device.

🧱 Project structure

dna-qr-auth-server/
├── app/
│   ├── main.py                # FastAPI routes + verification logic
│   ├── identity.py            # Native PQClean verifier wrapper (ctypes)
│   ├── storage.py             # In-memory session store
│   ├── config.py              # Environment-based settings
│   ├── qr.py                  # QR code generation (SVG)
│   ├── native/
│   │   ├── PQClean/           # PQClean source (vendored)
│   │   ├── dilithium_verify.c # C wrapper exposing dna_verify_mldsa87()
│   │   └── libdna_pq_verify.so
│   ├── templates/
│   │   ├── landing.html
│   │   └── success.html
│   └── static/
│       ├── app.js             # Browser polling + redirect logic
│       └── style.css          # CPUNK-themed styles
├── nginx/
│   └── default.conf           # Reverse proxy config
├── docker-compose.yml
├── Dockerfile
└── README.md

🚀 Run locally (Docker)
Requirements

Docker

Docker Compose

Start the server
docker compose up --build


Then open:

http://localhost:8081

⚙️ Configuration

Configuration is handled via environment variables (see app/config.py).

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


The QR Auth Server supports an optional identity allowlist using
app/known_identities.json.

This file controls which DNA identities are allowed to authenticate.
location : app/known_identities.json

🧠 How it works

The server always performs full cryptographic verification:

Fingerprint ↔ public key binding (SHA3-512)

Post-quantum signature verification (ML-DSA-87 / Dilithium-class)

After that, an optional policy check is applied:

Allowlist state	Result
File missing	✅ Open mode – any valid DNA identity may log in
File exists, empty list	✅ Open mode – any valid DNA identity may log in
File exists, contains fingerprints	🔒 Allowlist mode – only listed identities may log in
File exists but malformed	❌ Fail-closed – all logins denied

This means:
Security is never bypassed
The allowlist only restricts who may authenticate

📄 File format
✅ Empty allowlist (open mode)

Anyone with a valid DNA identity can authenticate.
{
  "fingerprints": []
}

Use this when:
    running a public service
    testing
    onboarding new users

🔒 Allowlist with one identity

Only the listed fingerprint is allowed.
{
  "fingerprints": [
    "deadbeefdeadbeefdeadbe...dbeefdeadbeefdeadbeefdeadbeef…"
  ]
}


    ⚠️ The fingerprint must be the full SHA3-512 hex string (128 characters).
    The example above is fake and elided.

Use this when:
    protecting admin access
    limiting access to a private service
    running production infrastructure


🧾 Audit logging

All allowlist decisions are recorded in the signature audit log:

approved

identity_not_allowed
fingerprint_pubkey_mismatch
invalid_signature
This provides a full forensic trail for authentication decisions.

🔄 Updating the allowlist

If the file is baked into the Docker image, you must rebuild:

docker compose build --no-cache
docker compose up -d


If the file is bind-mounted, a container restart is enough:

docker compose restart app



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
