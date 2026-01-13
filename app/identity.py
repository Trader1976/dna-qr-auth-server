# app/identity.py
import base64
from pathlib import Path
import ctypes
import json

# Minimal registry file (you can swap this to DHT/DB later)
_REG_PATH = Path(__file__).resolve().parent / "known_identities.json"

_native_lib = None


def resolve_pubkey_from_fingerprint(fingerprint: str) -> bytes | None:
    """
    Returns public key bytes for the given fingerprint, or None if unknown.

    known_identities.json format:
    {
      "<fingerprint_hex>": { "pubkey_b64": "<base64>" }
    }
    """
    if not _REG_PATH.exists():
        return None

    try:
        data = json.loads(_REG_PATH.read_text(encoding="utf-8"))
        entry = data.get(fingerprint)
        if not entry:
            return None
        pubkey_b64 = entry.get("pubkey_b64")
        if not pubkey_b64:
            return None
        return base64.b64decode(pubkey_b64, validate=True)
    except Exception:
        return None


# --- Native PQ signature verification (ML-DSA-87 / Dilithium5 class) ---

def _load_native_verifier():
    global _native_lib
    if _native_lib is not None:
        return _native_lib

    lib_path = Path(__file__).resolve().parent / "native" / "libdna_pq_verify.so"
    if not lib_path.exists():
        raise RuntimeError(f"Native verifier not found: {lib_path}")

    lib = ctypes.CDLL(str(lib_path))

    lib.dna_verify_mldsa87.argtypes = [
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # msg
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # sig
        ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,  # pk
    ]
    lib.dna_verify_mldsa87.restype = ctypes.c_int

    _native_lib = lib
    return lib


def verify_mldsa87_signature(pubkey: bytes, message: bytes, signature: bytes) -> bool:
    lib = _load_native_verifier()

    # Create stable C buffers (IMPORTANT)
    msg_buf = (ctypes.c_uint8 * len(message)).from_buffer_copy(message)
    sig_buf = (ctypes.c_uint8 * len(signature)).from_buffer_copy(signature)
    pk_buf  = (ctypes.c_uint8 * len(pubkey)).from_buffer_copy(pubkey)

    rc = lib.dna_verify_mldsa87(
        msg_buf, len(message),
        sig_buf, len(signature),
        pk_buf,  len(pubkey),
    )

    return bool(rc)
