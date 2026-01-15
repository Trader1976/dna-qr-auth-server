
<img width="492" height="539" alt="qr_auth" src="https://github.com/user-attachments/assets/1799f306-61e7-4de8-99ee-71e2965f6496" />


# DNA QR Authentication Server

**Last Updated:** 2026-01-15  
**Supported Protocols:** v4 (stateless), v3 (stateful)  
**License:** Apache-2.0

---

## Overview

This repository implements the **DNA QR Authentication Server** — a device‑mediated, post‑quantum authentication system based on QR codes and **native PQClean signature verification**.

It allows websites and applications to authenticate browser sessions **without passwords, cookies, or shared secrets**, using a trusted mobile device (**DNA‑Messenger**) as the cryptographic authority.

The design is inspired by WebAuthn/FIDO2, but extends it with:

* Post‑quantum cryptography
* Explicit relying‑party (RP) binding
* Stateless, CDN‑scale verification (v4)

---

## ✨ Key Features

* 📱 **Device‑mediated authentication** via QR codes
* 🔐 **Post‑quantum signatures** (ML‑DSA‑87 / Dilithium‑class)
* 🧬 **DNA identity** (fingerprint ↔ public‑key binding)
* 🧾 **Tamper‑evident audit logging** (hash‑chained)
* 🌍 **HTTPS‑only, phishing‑resistant RP binding**
* 🚀 **Stateless v4 mode** (Cloudflare / CDN‑friendly)
* 🔄 **Full backward compatibility** with v3

---

## Protocol Versions (Quick Overview)

| Version | Mode      | Description                                            | Status          |
| ------- | --------- | ------------------------------------------------------ | --------------- |
| v1      | Stateful  | Basic signing (origin, nonce)                          | Legacy          |
| v2      | Stateful  | + RP binding (`rp_id`)                                 | Supported       |
| v3      | Stateful  | + `rp_id_hash` in signed payload                       | Stable          |
| v4      | Stateless | Server‑signed tokens (`st` / `at`), no session storage | **Recommended** |

---

## Deployment Modes

### AUTH_MODE

The server behavior is controlled by the `AUTH_MODE` environment variable:

| Value  | Behavior                     |
| ------ | ---------------------------- |
| `v3`   | Enable **stateful v3 only**  |
| `v4`   | Enable **stateless v4 only** |
| `auto` | Enable **both**, prefer v4   |

Example (`docker-compose.yml`):

```yaml
environment:
  AUTH_MODE: v4
  ORIGIN: https://example.com
  RP_ID: example.com
  RP_NAME: Example Service
  SERVER_ED25519_SK_B64: <base64-key>
```

---

## Server‑Side Ed25519 Key (Required for v4)

Stateless v4 requires a **server‑owned Ed25519 signing key**.

This key:

* Is generated once by the operator
* Never leaves the server
* Is **not** a user identity
* Signs session (`st`) and approval (`at`) tokens

### Generate the key

```bash
python3 - <<'PY'
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

sk = Ed25519PrivateKey.generate()
raw = sk.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption(),
)
print(base64.b64encode(raw).decode())
PY
```

Add to `.env`:

```env
SERVER_ED25519_SK_B64=BASE64_VALUE
```

---

## Audit Logging

Both v3 **and v4** events are logged using the same **hash‑chained audit system**.

* Each entry includes the previous hash
* A `.state` file anchors the chain
* Logs are verifiable offline

Verification:

```bash
python3 verify_audit.py audit/signature_audit.jsonl \
  --state audit/signature_audit.state \
  --strict-chain \
  --strict-bytes
```

---

## Documentation

* 📄 **Protocol specification:** see [`PROTOCOL.md`](PROTOCOL.md)
* 🧪 Reference client: `dna_messenger_flutter/lib/services/qr_auth_service.dart`

---

## License

This project is licensed under the **Apache License 2.0**.

See the [LICENSE](LICENSE) file for details.
