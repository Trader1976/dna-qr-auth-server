# app/v4_tokens.py
#
# -----------------------------------------------------------------------------
# Architectural notes
# -----------------------------------------------------------------------------
# This module defines the *token layer* for protocol v4.
#
# Responsibilities:
#   - Create and verify compact, signed tokens used by the v4 stateless protocol
#   - Provide deterministic serialization (critical for cross-language safety)
#   - Remain cryptographically minimal and auditable
#
# What this module is:
#   - A tiny Ed25519-based signing/verification utility
#   - Similar in spirit to JWT, but intentionally simpler and stricter
#
# What this module is NOT:
#   - Not an identity system (user identity keys live elsewhere)
#   - Not a policy engine
#   - Not stateful
#
# Security model:
#   - Server holds ONE Ed25519 keypair (infrastructure key)
#   - Server signs:
#       * st  = session token (issued to browser → phone)
#       * at  = approval token (issued after phone verification)
#   - Tokens are:
#       * self-contained
#       * short-lived
#       * verifiable without DB access
#
# Token wire format (custom, JWT-like but simpler):
#
#     v4.<payload_b64url>.<signature_b64url>
#
# Where:
#   - payload is canonical JSON (sorted keys, no whitespace)
#   - signature = Ed25519.sign(payload_bytes)
#
# This explicit design avoids JWT pitfalls:
#   - no alg confusion
#   - no headers
#   - no implicit claims
#   - no JSON normalization ambiguity
# -----------------------------------------------------------------------------


import base64
import hashlib
import json
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


# -----------------------------------------------------------------------------
# Base64 helpers
# -----------------------------------------------------------------------------
def b64url_encode(b: bytes) -> str:
    """
    URL-safe Base64 encoding WITHOUT padding.

    Used for token transport:
      - safe in URLs / QR codes
      - compact
      - deterministic

    Padding is stripped to reduce QR density.
    """
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def b64url_decode(s: str) -> bytes:
    """
    Decode URL-safe Base64 with optional missing padding.

    Padding is restored automatically to allow lenient decoding.
    """
    s = str(s).strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def b64_std(b: bytes) -> str:
    """
    Standard Base64 encoding WITH padding.

    Used where strict WebAuthn-style compatibility is required
    (e.g. rp_id_hash).
    """
    return base64.b64encode(b).decode("ascii")


def sha256_b64_std(s: str) -> str:
    """
    Convenience helper:
      base64( SHA-256(utf8(s)) )

    Matches the rp_id_hash style used elsewhere in the protocol.
    """
    return b64_std(hashlib.sha256(s.encode("utf-8")).digest())


# -----------------------------------------------------------------------------
# Key loading
# -----------------------------------------------------------------------------
def load_ed25519_private_key_from_b64(sk_b64: str) -> Ed25519PrivateKey:
    """
    Load a raw Ed25519 private key from Base64.

    Architectural constraints:
      - The key MUST be exactly 32 bytes (raw Ed25519 seed)
      - No PEM, no headers, no metadata
      - Keeps deployment simple (env var friendly)

    This key represents *server authority*, not user identity.
    """
    raw = base64.b64decode(sk_b64.strip(), validate=True)
    if len(raw) != 32:
        raise ValueError("Ed25519 raw private key must be 32 bytes (base64 of 32 bytes)")
    return Ed25519PrivateKey.from_private_bytes(raw)


# -----------------------------------------------------------------------------
# Token wire format helpers
# -----------------------------------------------------------------------------
def encode_token_v4(payload_bytes: bytes, sig: bytes) -> str:
    """
    Assemble a v4 token from payload bytes and signature.

    Format:
        v4.<payload_b64url>.<signature_b64url>

    Version prefix is explicit to allow:
      - protocol evolution
      - clean rejection of unknown formats
    """
    return "v4." + b64url_encode(payload_bytes) + "." + b64url_encode(sig)


def decode_token_v4(token: str) -> Tuple[bytes, bytes]:
    """
    Parse a v4 token into payload bytes and signature.

    This performs *format validation only*.
    Cryptographic verification happens separately.
    """
    parts = str(token).split(".")
    if len(parts) != 3 or parts[0] != "v4":
        raise ValueError("bad token format")

    payload_bytes = b64url_decode(parts[1])
    sig = b64url_decode(parts[2])
    return payload_bytes, sig


# -----------------------------------------------------------------------------
# Signing
# -----------------------------------------------------------------------------
def sign_token_v4(sk: Ed25519PrivateKey, payload_obj: dict) -> str:
    """
    Sign a payload object into a v4 token.

    Critical design decision:
      - JSON is serialized with:
          * sorted keys
          * no whitespace
      - This guarantees byte-for-byte determinism across languages.

    Determinism is ESSENTIAL:
      - signature validity depends on identical byte streams
      - prevents subtle cross-platform mismatches
    """
    payload_bytes = json.dumps(
        payload_obj,
        separators=(",", ":"),   # no whitespace
        sort_keys=True           # stable key order
    ).encode("utf-8")

    sig = sk.sign(payload_bytes)
    return encode_token_v4(payload_bytes, sig)


# -----------------------------------------------------------------------------
# Verification
# -----------------------------------------------------------------------------
def verify_token_v4(pk: Ed25519PublicKey, token: str) -> dict:
    """
    Verify a v4 token and return its decoded payload.

    Steps:
      1. Decode token structure
      2. Verify Ed25519 signature over raw payload bytes
      3. Parse JSON payload

    Raises:
      - ValueError / InvalidSignature on failure

    IMPORTANT:
      - This function does NOT enforce semantic rules
        (expiry, typ, rp binding, etc).
      - Callers MUST validate claims themselves.
    """
    payload_bytes, sig = decode_token_v4(token)
    pk.verify(sig, payload_bytes)
    return json.loads(payload_bytes.decode("utf-8"))
