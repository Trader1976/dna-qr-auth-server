# DNA QR Authentication Protocol

**Last Updated:** 2026-01-15  
**Current Versions:** v4 (stateless), v3 (stateful)

---

## 1. Design Goals

* Passwordless authentication
* Device‑mediated approval
* Post‑quantum security
* Phishing resistance
* Offline‑verifiable audit trail
* CDN‑scale stateless verification (v4)

---

## 2. Actors

* **Browser** – requests authentication
* **Auth Server** – verifies signatures and policy
* **DNA‑Messenger App** – holds user private keys

---

## 3. Cryptography

| Component            | Algorithm                   |
| -------------------- | --------------------------- |
| User signatures      | ML‑DSA‑87 (Dilithium‑class) |
| Server tokens        | Ed25519                     |
| Identity fingerprint | SHA3‑512(pubkey)            |
| RP binding           | SHA‑256 + Base64            |

---

## 4. Protocol v3 (Stateful)

### Characteristics

* Server stores session state
* Browser polls `/api/v1/session/{id}`
* Suitable for single‑node deployments

### Canonical Payload (v3)

```json
{"expires_at":1700000000,"issued_at":1699999900,"nonce":"...","origin":"https://example.com","rp_id":"example.com","rp_id_hash":"...","session_id":"..."}
```

---

## 5. Protocol v4 (Stateless)

### Characteristics

* No server‑side session storage
* Server signs **session token (`st`)**
* Phone signs canonical payload
* Server issues **approval token (`at`)**
* Browser polls `/api/v4/status`

### Token Types

| Token | Signed By | Purpose            |
| ----- | --------- | ------------------ |
| `st`  | Server    | Session descriptor |
| `at`  | Server    | Approval proof     |

---

## 6. v4 Flow

1. Browser requests `/api/v4/session`
2. Server returns `st` + QR URI
3. Phone scans QR
4. Phone verifies origin + RP binding
5. Phone signs canonical payload
6. Server verifies and issues `at`
7. Browser polls and redirects

---

## 7. Canonical Payload (v4)

```json
{"expires_at":1700000000,"issued_at":1699999900,"nonce":"...","origin":"https://example.com","rp_id_hash":"...","session_id":"...","sid":"...","st_hash":"..."}
```

---

## 8. Security Guarantees

* No shared secrets
* No password reuse
* Replay‑safe (nonce + expiry)
* Phishing‑resistant RP binding
* PQ‑secure signatures
* Audit‑verifiable decisions

---

## 9. Downgrade Protection

* Protocol version is explicit
* v4 endpoints reject v3 payloads
* v3 enforces minimum version

---

## 10. Audit Logging

All decisions (approve / deny / error) are recorded with:

* Canonical bytes hash
* Signature hash
* Previous hash (chain)

This enables offline verification and forensic analysis.

---

## 11. Compatibility Notes

* v3 remains fully supported
* v4 recommended for production
* AUTH_MODE controls exposure

---

*End of specification.*
