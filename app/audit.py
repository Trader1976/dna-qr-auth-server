import json
import os
import time
import hashlib
from pathlib import Path
from typing import Any, Dict, Optional

from .config import settings


def _now_ms() -> int:
    return int(time.time() * 1000)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_trunc(s: Optional[str], n: int = 256) -> Optional[str]:
    if s is None:
        return None
    s = str(s)
    return s if len(s) <= n else s[:n] + "…"


def audit_log_path() -> Path:
    """
    Default audit log path:
      ./audit/signature_audit.jsonl (relative to app/)
    Override via settings.AUDIT_LOG_PATH if you add it.
    """
    p = getattr(settings, "AUDIT_LOG_PATH", None)
    if p:
        return Path(p)
    base = Path(__file__).resolve().parent
    return base / "audit" / "signature_audit.jsonl"


def append_event(event: Dict[str, Any]) -> None:
    """
    Append-only JSONL audit log.
    Best-effort: audit failure must NOT break auth flow.
    """
    try:
        path = audit_log_path()
        path.parent.mkdir(parents=True, exist_ok=True)

        # Make sure every record has a timestamp
        event.setdefault("ts_ms", _now_ms())

        line = json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        # Never let audit logging break authentication
        pass


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
    ev: Dict[str, Any] = {
        "event": "qr_auth_signature",
        "session_id": session_id,
        "fingerprint": claimed_fp,
        "pubkey_fp": pubkey_fp,
        "origin": origin,
        "nonce": nonce,
        "client_ip": request_ip,
        "user_agent": _safe_trunc(user_agent, 180),
    }
    if canonical_bytes is not None:
        ev["canonical_sha256"] = _sha256_hex(canonical_bytes)
        ev["canonical_len"] = len(canonical_bytes)
    if signature_bytes is not None:
        ev["sig_sha256"] = _sha256_hex(signature_bytes)
        ev["sig_len"] = len(signature_bytes)
    return ev
