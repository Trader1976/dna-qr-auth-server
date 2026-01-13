"""
app/identity.py

Identity registry + native PQ signature verification.

Key points:
- The phone sends:
  - fingerprint (sha3_512(pubkey) hex)
  - pubkey_b64 (raw public key bytes, Base64)
  - signature (raw signature bytes, Base64)
- Server verifies:
  1) fingerprint matches pubkey (sha3_512)
  2) signature verifies via PQClean (ML-DSA-87 / Dilithium5-class)

This module also supports an OPTIONAL "known identities" allowlist:
- If the allowlist is empty -> OPEN MODE (any valid DNA identity may login)
- If the allowlist contains fingerprints -> ALLOWLIST MODE (only listed identities may login)

File: app/known_identities.json (lives alongside this file)

Supported formats:

1) New/simple allowlist format:
   {
     "fingerprints": ["<fp1>", "<fp2>"]
   }

2) Legacy registry format (fingerprint -> entry dict):
   {
     "<fp1>": { "pubkey_b64": "....", "nick": "..." },
     "<fp2>": { "pubkey_b64": "...." }
   }

In legacy format, the keys themselves count as allowed fingerprints (allowlist),
and you can optionally resolve pubkey from fingerprint for other future flows.
"""

import base64
import ctypes
import json
from pathlib import Path
from typing import Any, Dict, Optional, Set


# -----------------------------------------------------------------------------
# Paths / globals
# -----------------------------------------------------------------------------

# known_identities.json lives alongside this file
KNOWN_IDENTITIES_PATH = Path(__file__).resolve().parent / "known_identities.json"

# Cache the loaded shared library so we load it only once per process
_native_lib = None


# -----------------------------------------------------------------------------
# Base64 helper
# -----------------------------------------------------------------------------
def _b64decode_loose(s: str) -> bytes:
    """
    Standard base64 decode with optional padding.

    We accept missing '=' padding (common in URL-safe variants),
    but we still validate characters to reject garbage input.
    """
    s = str(s).strip()
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s, validate=True)


# -----------------------------------------------------------------------------
# Registry helpers (optional / future use)
# -----------------------------------------------------------------------------
def _load_known_identities_raw() -> Dict[str, Any]:
    """
    Load known_identities.json as a dict.

    Returns {} if file does not exist or is invalid JSON.
    """
    if not KNOWN_IDENTITIES_PATH.exists():
        return {}

    try:
        return json.loads(KNOWN_IDENTITIES_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def resolve_pubkey_from_fingerprint(fingerprint: str) -> Optional[bytes]:
    """
    Resolve a fingerprint to a public key using a local registry.

    Works with legacy registry format:
      {
        "<fingerprint_hex_lower>": { "pubkey_b64": "<base64>" }
      }

    NOTE:
    - In your CURRENT flow, the client sends pubkey_b64 directly,
      so this is not required for verification.
    - This exists for future use (e.g. server-side lookup, account mapping).
    """
    fp = str(fingerprint).lower().strip()
    data = _load_known_identities_raw()
    entry = data.get(fp)

    if not isinstance(entry, dict):
        return None

    pubkey_b64 = entry.get("pubkey_b64")
    if not pubkey_b64:
        return None

    try:
        return _b64decode_loose(pubkey_b64)
    except Exception:
        return None


# -----------------------------------------------------------------------------
# Allowlist support
# -----------------------------------------------------------------------------
def load_allowed_fingerprints() -> Set[str]:
    """
    Load allowed fingerprints from known_identities.json.

    Supports two formats:

    A) Allowlist format:
       {"fingerprints": ["<fp1>", "<fp2>"]}

    B) Legacy registry format:
       {"<fp1>": {...}, "<fp2>": {...}}
       In this case, the dict keys are treated as allowed fingerprints.

    Returns a set of lowercase fingerprint hex strings.
    Returns empty set if file missing/invalid or no fingerprints present.
    """
    data = _load_known_identities_raw()
    if not isinstance(data, dict) or not data:
        return set()

    # Format A: {"fingerprints": [...]}
    fps = data.get("fingerprints")
    if isinstance(fps, list):
        out: Set[str] = set()
        for fp in fps:
            if isinstance(fp, str) and fp.strip():
                out.add(fp.strip().lower())
        return out

    # Format B: legacy registry dict -> allowed fingerprints are the keys
    # We only accept keys that look like SHA3-512 hex (128 chars), but we keep it permissive:
    out = set()
    for k in data.keys():
        if isinstance(k, str) and k.strip():
            out.add(k.strip().lower())
    return out


def is_fingerprint_allowed(fp: str) -> bool:
    """
    Decide whether a fingerprint is allowed.

    Allowlist mode:
      - If known_identities.json contains >= 1 fingerprint -> only those are allowed.
    Open mode:
      - If allowlist is empty -> anyone is allowed (as long as signature verifies).

    IMPORTANT:
    - In main.py, you should pass the *computed* fingerprint (sha3_512(pubkey)),
      not the claimed fingerprint, because computed is authoritative.
    """
    fp = str(fp).strip().lower()
    allowed = load_allowed_fingerprints()

    # Empty allowlist => open mode
    if len(allowed) == 0:
        return True

    return fp in allowed


# -----------------------------------------------------------------------------
# Native PQClean verifier loader
# -----------------------------------------------------------------------------
def _load_native_verifier():
    """
    Loads app/native/libdna_pq_verify.so which must export:

        int dna_verify_mldsa87(
            const uint8_t* msg, size_t msg_len,
            const uint8_t* sig, size_t sig_len,
            const uint8_t* pk,  size_t pk_len
        );

    Returns a ctypes.CDLL handle.

    This function caches the loaded library handle globally so it is loaded once.
    """
    global _native_lib
    if _native_lib is not None:
        return _native_lib

    lib_path = Path(__file__).resolve().parent / "native" / "libdna_pq_verify.so"
    if not lib_path.exists():
        raise RuntimeError(f"Native verifier not found: {lib_path}")

    lib = ctypes.CDLL(str(lib_path))

    # Define argument/return types precisely (important!)
    lib.dna_verify_mldsa87.argtypes = [
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # msg, msg_len
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # sig, sig_len
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # pk, pk_len
    ]
    lib.dna_verify_mldsa87.restype = ctypes.c_int

    _native_lib = lib
    return lib


# -----------------------------------------------------------------------------
# Signature verification (native PQClean)
# -----------------------------------------------------------------------------
def verify_mldsa87_signature(pubkey: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify ML-DSA-87 signature using the native PQClean verifier.

    We allocate stable C buffers (from_buffer_copy) so memory stays valid
    for the duration of the call.

    Returns:
      True  -> signature valid
      False -> signature invalid

    Notes:
    - The C function should return 1/true for success and 0/false for failure
      (your code uses bool(rc), so anything nonzero means valid).
    """
    lib = _load_native_verifier()

    if not isinstance(pubkey, (bytes, bytearray)):
        raise TypeError("pubkey must be bytes")
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")
    if not isinstance(signature, (bytes, bytearray)):
        raise TypeError("signature must be bytes")

    # IMPORTANT:
    # from_buffer_copy creates a new buffer so we are not referencing Python-managed memory.
    msg_buf = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
    sig_buf = (ctypes.c_uint8 * len(signature)).from_buffer_copy(signature)
    pk_buf = (ctypes.c_uint8 * len(pubkey)).from_buffer_copy(pubkey)

    rc = lib.dna_verify_mldsa87(
        msg_buf,
        len(message),
        sig_buf,
        len(signature),
        pk_buf,
        len(pubkey),
    )

    return bool(rc)
