from pathlib import Path
import json
import time
import hashlib
import os
import base64
from datetime import datetime, timezone

from .config import settings

# -----------------------------------------------------------------------------
# Paths (single source of truth)
# -----------------------------------------------------------------------------
AUDIT_LOG_PATH = Path(settings.AUDIT_LOG_PATH)
AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
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


def _now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _now_iso_local() -> str:
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def _json_default(o):
    """
    Make audit logging robust: convert non-JSON types (notably bytes) to JSON-safe objects.
    """
    if isinstance(o, (bytes, bytearray, memoryview)):
        b = bytes(o)
        # Keep logs usable: include length and sha3_256; include b64 only if needed later.
        return {
            "_type": "bytes",
            "len": len(b),
            "sha3_256": hashlib.sha3_256(b).hexdigest(),
            "b64": base64.b64encode(b).decode("ascii"),
        }
    if isinstance(o, Path):
        return str(o)
    return str(o)

# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------
def build_common(**kwargs):
    common = {
        "ts": int(time.time()),
        "ts_iso": _now_iso_local(),  # local time
    }
    common.update({k: v for k, v in kwargs.items() if v is not None})
    return common


def append_event(event: dict) -> None:
    # Ensure timestamps
    if "ts" not in event:
        event["ts"] = int(time.time())
    if "ts_iso" not in event:
        event["ts_iso"] = _now_iso_local()

    # Ensure directory exists
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Load chain head, attach prev_hash
    prev_hash = _load_prev_hash()
    event["prev_hash"] = prev_hash

    # Compute hash over canonical JSON of event WITHOUT "hash"
    tmp = dict(event)
    tmp.pop("hash", None)
    payload = json.dumps(
        tmp,
        sort_keys=True,
        ensure_ascii=False,
        default=_json_default,
        separators=(",", ":"),
    )
    h = hashlib.sha3_256(payload.encode("utf-8")).hexdigest()
    event["hash"] = h

    # Write final event INCLUDING "hash"
    final_line = json.dumps(
        event,
        sort_keys=True,
        ensure_ascii=False,
        default=_json_default,
        separators=(",", ":"),
    )
    with AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(final_line + "\n")

    # Persist chain head
    _store_prev_hash(h)
