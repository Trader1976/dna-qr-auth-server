import time, secrets
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Any

class SessionStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"

@dataclass
class Session:
    session_id: str
    nonce: str
    origin: str
    callback_url: str
    issued_at: int
    expires_at: int
    status: SessionStatus = SessionStatus.PENDING
    response: Optional[Dict[str, Any]] = None

    @property
    def is_expired(self) -> bool:
        return int(time.time()) >= self.expires_at

    @property
    def qr_payload_json(self) -> str:
        # This is what you encode in QR
        # Your phone-side parser expects: origin, session_id, nonce, callback, expires_at (optional)
        import json
        payload = {
            "type": "dna.auth.request",
            "v": 1,
            "origin": self.origin,
            "session_id": self.session_id,
            "nonce": self.nonce,
            "callback": self.callback_url,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }
        return json.dumps(payload, separators=(",", ":"))

    def public_view(self):
        st = self.status
        if self.is_expired and st == SessionStatus.PENDING:
            st = SessionStatus.EXPIRED
        return {
            "session_id": self.session_id,
            "origin": self.origin,
            "status": st,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

class InMemoryStore:
    def __init__(self):
        self.sessions: Dict[str, Session] = {}

    def create_session(self, origin: str, ttl_seconds: int, callback_url: str) -> Session:
        now = int(time.time())
        session_id = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(18)
        sess = Session(
            session_id=session_id,
            nonce=nonce,
            origin=origin,
            callback_url=callback_url,
            issued_at=now,
            expires_at=now + ttl_seconds,
        )
        self.sessions[session_id] = sess
        return sess

    def get(self, session_id: str) -> Optional[Session]:
        return self.sessions.get(session_id)

    def set_status(self, session_id: str, status: SessionStatus):
        sess = self.sessions.get(session_id)
        if sess:
            sess.status = status

    def save_response(self, session_id: str, resp: Dict[str, Any]):
        sess = self.sessions.get(session_id)
        if sess:
            sess.response = resp

    def matches_issued_payload(self, session_id: str, signed_payload: Dict[str, Any]) -> bool:
        sess = self.sessions.get(session_id)
        if not sess:
            return False
        # must match these exactly:
        return (
            signed_payload.get("origin") == sess.origin and
            signed_payload.get("session_id") == sess.session_id and
            signed_payload.get("nonce") == sess.nonce and
            int(signed_payload.get("expires_at", 0)) == sess.expires_at
        )

store = InMemoryStore()
