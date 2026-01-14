import time
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Any, List
from urllib.parse import urlencode


def b64url_token(nbytes: int) -> str:
    # token_urlsafe returns base64url-ish without padding; good enough
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

    # RP context (WebAuthn-like)
    rp_id: str
    rp_name: str
    scopes: List[str]

    # QR payload versioning
    payload_version: int = 2

    status: SessionStatus = SessionStatus.PENDING
    response: Optional[Dict[str, Any]] = None

    @property
    def is_expired(self) -> bool:
        return int(time.time()) >= self.expires_at

    @property
    def qr_uri(self) -> str:
        """
        Build the QR payload (dna:// URI).

        v2 adds explicit RP context:
          - rp_id (domain-only)
          - rp_name
          - scopes

        NOTE: We URL-encode all values to avoid breaking parsing when
        origin/callback contains reserved characters.
        """
        base = self.origin.rstrip("/")
        callback = f"{base}/api/v1/session/{self.session_id}/complete"

        params = {
            "v": str(self.payload_version),
            "origin": base,
            "session_id": self.session_id,
            "nonce": self.nonce,
            "callback": callback,

            # RP binding fields (first-class)
            "rp_id": self.rp_id,
            "rp_name": self.rp_name,
            "scopes": ",".join(self.scopes),
        }

        return "dna://auth?" + urlencode(params, safe=":/")

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

    def create_session(self, origin: str, ttl_seconds: int, rp_id: str, rp_name: str, scopes: List[str]) -> Session:
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
            rp_id=rp_id,
            rp_name=rp_name,
            scopes=scopes,
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
