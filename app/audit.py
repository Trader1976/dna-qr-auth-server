from pathlib import Path
import json
import time
import hashlib

from .config import settings


# -----------------------------------------------------------------------------
# Paths (single source of truth)
# -----------------------------------------------------------------------------
AUDIT_LOG_PATH = Path(settings.AUDIT_LOG_PATH)

# Ensure directory exists (host-mounted volume)
AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

# State file for hash chaining
AUDIT_STATE_PATH = AUDIT_LOG_PATH.with_suffix(".state")


# -----------------------------------------------------------------------------
# Internal helpers
# -----------------------------------------------------------------------------
def _load_prev_hash() -> str:
    if AUDIT_STATE_PATH.exists():
        return AUDIT_STATE_PATH.read_text().strip()
    return "0" * 64


def _store_prev_hash(h: str):
    AUDIT_STATE_PATH.write_text(h)


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------
def build_common(
    *,
    session_id: str,
    claimed_fp: str | None = None,
    pubkey_fp: str | None = None,
    canonical_bytes: bytes | None = None,
    signature_bytes: bytes | None = None,
    origin: str | None = None,
    nonce: str | None = None,
    request_ip: str | None = None,
    user_agent: str | None = None,
):
    event = {
        "ts": int(time.time()),
        "session_id": session_id,
        "origin": origin,
        "nonce": nonce,
        "request_ip": request_ip,
        "user_agent": user_agent,
        "fingerprint": claimed_fp,
        "pubkey_fp": pubkey_fp,
    }

    if canonical_bytes is not None:
        event["canonical_len"] = len(canonical_bytes)
        event["canonical_sha3_256"] = hashlib.sha3_256(canonical_bytes).hexdigest()

    if signature_bytes is not None:
        event["signature_len"] = len(signature_bytes)
        event["signature_sha3_256"] = hashlib.sha3_256(signature_bytes).hexdigest()

    return event


def append_event(event: dict):
    prev_hash = _load_prev_hash()

    record = {
        **event,
        "prev_hash": prev_hash,
    }

    encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    h = hashlib.sha3_256(encoded).hexdigest()

    record["hash"] = h

    with AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

    _store_prev_hash(h)
