"""
app/audit.py

Tamper-evident signature audit log.

We append one JSON object per line (JSONL). Each event is hash-chained:

  H_0 = "0"*64
  H_n = SHA3-256( bytes.fromhex(H_{n-1}) || canonical_json(event_without_hash_fields) )

Each line stores:
  - prev_hash: hex string (64 chars)
  - hash:      hex string (64 chars)

Properties:
- Any modification, deletion, or reordering of log lines breaks the chain.
- Chain state is persisted in audit/signature_audit.state
- Uses file locking (flock) to keep chain consistent under concurrency.
"""

from __future__ import annotations

import json
import os
import time
import hashlib
from pathlib import Path
from typing import Any, Dict, Optional

# Linux file lock (works in Docker/Linux)
import fcntl


# -----------------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
AUDIT_DIR = BASE_DIR.parent / "audit"
AUDIT_LOG_PATH = AUDIT_DIR / "signature_audit.jsonl"
AUDIT_STATE_PATH = AUDIT_DIR / "signature_audit.state"
AUDIT_LOCK_PATH = AUDIT_DIR / "signature_audit.lock"

GENESIS_HASH = "0" * 64  # 32 bytes hex


# -----------------------------------------------------------------------------
# Canonical JSON
# -----------------------------------------------------------------------------
def _canonical_json_bytes(obj: Dict[str, Any]) -> bytes:
    """
    Produce deterministic JSON bytes for hashing and logging:
    - sorted keys
    - no whitespace
    - UTF-8
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha3_256_hex(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()


def _read_last_hash_unlocked() -> str:
    """
    Read last hash from the state file. Caller must hold lock.
    Returns GENESIS_HASH if state missing/empty.
    """
    try:
        if not AUDIT_STATE_PATH.exists():
            return GENESIS_HASH
        s = AUDIT_STATE_PATH.read_text(encoding="utf-8").strip()
        if len(s) != 64:
            return GENESIS_HASH
        # validate hex
        bytes.fromhex(s)
        return s.lower()
    except Exception:
        return GENESIS_HASH


def _write_last_hash_unlocked(h: str) -> None:
    """
    Persist last hash to state file. Caller must hold lock.
    """
    AUDIT_STATE_PATH.write_text(h + "\n", encoding="utf-8")


def _ensure_dirs() -> None:
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)


# -----------------------------------------------------------------------------
# Public helpers used by main.py
# -----------------------------------------------------------------------------
def build_common(
    *,
    session_id: str,
    claimed_fp: Optional[str] = None,
    pubkey_fp: Optional[str] = None,
    canonical_bytes: Optional[bytes] = None,
    signature_bytes: Optional[bytes] = None,
    origin: Optional[str] = None,
    nonce: Optional[str] = None,
    request_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build common audit fields. Keep this "boring" and stable.

    Note:
    - We store hashes/lengths of large byte blobs rather than raw bytes,
      so logs stay small and less sensitive.
    """
    out: Dict[str, Any] = {
        "ts": int(time.time()),
        "session_id": session_id,
    }

    if claimed_fp:
        out["fingerprint"] = claimed_fp
    if pubkey_fp:
        out["pubkey_fp"] = pubkey_fp
    if origin:
        out["origin"] = origin
    if nonce:
        out["nonce"] = nonce
    if request_ip:
        out["request_ip"] = request_ip
    if user_agent:
        out["user_agent"] = user_agent[:200]

    if canonical_bytes is not None:
        out["canonical_len"] = len(canonical_bytes)
        out["canonical_sha3_256"] = _sha3_256_hex(canonical_bytes)

    if signature_bytes is not None:
        out["signature_len"] = len(signature_bytes)
        out["signature_sha3_256"] = _sha3_256_hex(signature_bytes)

    return out


def append_event(event: Dict[str, Any]) -> None:
    """
    Append one event to the audit log with hash chaining.

    The function:
    - locks AUDIT_LOCK_PATH
    - reads prev hash
    - computes next hash over canonical event (excluding hash fields)
    - writes JSONL line containing prev_hash + hash
    - updates state file
    """
    _ensure_dirs()

    # We lock a dedicated lock file so it works even if log/state don't exist yet.
    with open(AUDIT_LOCK_PATH, "a+", encoding="utf-8") as lockf:
        fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)

        prev_hash = _read_last_hash_unlocked()

        # Never allow callers to inject their own chain fields.
        e = dict(event)
        e.pop("prev_hash", None)
        e.pop("hash", None)

        # Canonicalize event *without* chain fields
        canon = _canonical_json_bytes(e)

        # Chain: SHA3-256(prev_hash_bytes || canon_event_bytes)
        next_hash = _sha3_256_hex(bytes.fromhex(prev_hash) + canon)

        # Record both chain fields into the final stored event
        stored = dict(e)
        stored["prev_hash"] = prev_hash
        stored["hash"] = next_hash

        line = _canonical_json_bytes(stored) + b"\n"

        # Append to log
        with open(AUDIT_LOG_PATH, "ab") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())

        # Update state
        _write_last_hash_unlocked(next_hash)

        fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)


# -----------------------------------------------------------------------------
# Optional verification utility (can be used manually)
# -----------------------------------------------------------------------------
def verify_log_chain(path: Path = AUDIT_LOG_PATH) -> bool:
    """
    Verify the hash chain of an audit log file.
    Returns True if valid, False otherwise.
    """
    if not path.exists():
        return True

    prev = GENESIS_HASH
    try:
        with open(path, "rb") as f:
            for raw_line in f:
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                obj = json.loads(raw_line.decode("utf-8"))

                line_prev = obj.get("prev_hash")
                line_hash = obj.get("hash")
                if line_prev != prev:
                    return False

                # recompute from event excluding hash fields
                obj2 = dict(obj)
                obj2.pop("prev_hash", None)
                obj2.pop("hash", None)

                canon = _canonical_json_bytes(obj2)
                expect = _sha3_256_hex(bytes.fromhex(prev) + canon)

                if expect != line_hash:
                    return False

                prev = line_hash

        return True
    except Exception:
        return False
