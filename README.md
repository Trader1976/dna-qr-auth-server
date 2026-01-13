# DNA QR Auth Server

A QR-code–based authentication server for **DNA-Messenger**, designed for secure, device-mediated login flows and post-quantum identity verification.

This service enables a website or application to authenticate a user by displaying a QR code, which is scanned and approved in the DNA-Messenger mobile app. The browser session is then approved without passwords, cookies, or shared secrets.

---

## ✨ Features

- QR-based login / authorization flow
- Device-mediated approval via DNA-Messenger
- Session-based authentication (pending → approved / denied / expired)
- Stateless browser polling (no WebSockets required)
- Post-quantum–ready signature model (Dilithium via DNA engine)
- Dockerized FastAPI backend
- Nginx reverse proxy support
- Works locally and via Cloudflare Tunnel

---

## 🧠 How it works (high level)

1. **Browser opens login page**
   - Server creates a short-lived auth session
   - QR code is rendered with a `dna://auth` payload

2. **User scans QR code with DNA-Messenger**
   - App validates payload
   - User approves or denies the request
   - App signs a canonical payload with the user’s DNA identity
   - Signed response is POSTed back to the server

3. **Server verifies and stores result**
   - Session status becomes `approved`, `denied`, or `expired`

4. **Browser polls session status**
   - When approved, browser redirects to `/success`

This flow is similar in spirit to GitHub Device Login or WalletConnect, but designed for decentralized and post-quantum identity systems.

---

## 🧱 Project structure

dna-qr-auth-server/
├── app/
│ ├── main.py # FastAPI routes
│ ├── storage.py # In-memory session store
│ ├── config.py # Environment-based settings
│ ├── qr.py # QR code generation
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

You can override them via .env or docker-compose.yml.

🧪 Status

✅ QR auth flow working end-to-end

✅ Mobile approval + server verification

✅ Browser redirect on approval

🚧 Signature verification hardening

🚧 Persistent storage (currently in-memory)

This project is experimental and under active development.

🔐 Security notes

No passwords are exchanged

No cookies are required for auth

Sessions are short-lived

Nonces prevent replay

Signature verification is designed for post-quantum cryptography

Do not use in production without review and hardening.

📄 License

To be decided (MIT / Apache-2.0 recommended).

🧬 Related projects

DNA-Messenger

CPUNK Protocol

Post-quantum identity & messaging stack

🤝 Contributing

Issues and pull requests are welcome.
This project is part of a broader experimental identity ecosystem.
