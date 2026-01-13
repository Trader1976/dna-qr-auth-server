import time, secrets
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Any, List


def b64url_token(nbytes: int) -> str:
    # token_urlsafe returns base64url-ish without padding; good enough for v1
    return secrets.token_urlsafe(nbytes)


class SessionStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


@dataclass
class Session:
    session_id: str
    challenge: str
    origin: str
    issued_at: int
    expires_at: int
    nonce: str
    status: SessionStatus = SessionStatus.PENDING
    response: Optional[Dict[str, Any]] = None

    @property
    def is_expired(self) -> bool:
        return int(time.time()) >= self.expires_at

    @property
    def qr_uri(self) -> str:
        base = self.origin.rstrip("/")
        callback = f"{base}/api/v1/session/{self.session_id}/complete"
        return (
            "dna://auth?"
            "v=1"
            f"&origin={base}"
            f"&session_id={self.session_id}"
            f"&nonce={self.nonce}"
            f"&callback={callback}"
        )

    def public_view(self):
        st = self.status
        if self.is_expired and st == SessionStatus.PENDING:
            st = SessionStatus.EXPIRED
        return {
            "v": 1,
            "session_id": self.session_id,
            "origin": self.origin,
            "status": st,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


class InMemoryStore:
    def __init__(self):
        self.sessions: Dict[str, Session] = {}
        self.nonces_seen: Dict[str, set[str]] = {}

    def create_session(self, origin: str, ttl_seconds: int) -> Session:
        now = int(time.time())
        session_id = b64url_token(24)
        challenge = b64url_token(32)
        nonce = b64url_token(16)
        sess = Session(
            session_id=session_id,
            challenge=challenge,
            origin=origin,
            issued_at=now,
            expires_at=now + ttl_seconds,
            nonce=nonce,
        )
        self.sessions[session_id] = sess
        self.nonces_seen[session_id] = set()
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

    def seen_nonce(self, session_id: str, nonce: str) -> bool:
        s = self.nonces_seen.get(session_id)
        if s is None:
            return True
        if nonce in s:
            return True
        s.add(nonce)
        return False


store = InMemoryStore()
