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
"""

import base64
import ctypes
import json
from pathlib import Path

# known_identities.json lives alongside this file
_REG_PATH = Path(__file__).resolve().parent / "known_identities.json"

# Cache the loaded shared library so we load it only once
_native_lib = None


def _b64decode_loose(s: str) -> bytes:
    """
    Standard base64 decode with optional padding.
    """
    s = str(s).strip()
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s, validate=True)


def resolve_pubkey_from_fingerprint(fingerprint: str) -> bytes | None:
    """
    Resolve a fingerprint to a public key using a local registry.

    known_identities.json format:
    {
      "<fingerprint_hex_lower>": { "pubkey_b64": "<base64>" }
    }

    NOTE: In your current flow, the client sends pubkey_b64 directly,
    so this registry is optional/future use.
    """
    if not _REG_PATH.exists():
        return None

    fp = str(fingerprint).lower().strip()

    try:
        data = json.loads(_REG_PATH.read_text(encoding="utf-8"))
        entry = data.get(fp)
        if not entry:
            return None
        pubkey_b64 = entry.get("pubkey_b64")
        if not pubkey_b64:
            return None
        return _b64decode_loose(pubkey_b64)
    except Exception:
        return None


def _load_native_verifier():
    """
    Loads app/native/libdna_pq_verify.so which must export:

        int dna_verify_mldsa87(
            const uint8_t* msg, size_t msg_len,
            const uint8_t* sig, size_t sig_len,
            const uint8_t* pk,  size_t pk_len
        );

    Returns a ctypes.CDLL handle.
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


def verify_mldsa87_signature(pubkey: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify ML-DSA-87 signature using the native PQClean verifier.

    We must allocate stable C buffers (from_buffer_copy) so the memory stays valid
    for the duration of the call.
    """
    lib = _load_native_verifier()

    if not isinstance(pubkey, (bytes, bytearray)):
        raise TypeError("pubkey must be bytes")
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")
    if not isinstance(signature, (bytes, bytearray)):
        raise TypeError("signature must be bytes")

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
