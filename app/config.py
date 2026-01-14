from urllib.parse import urlparse
from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    ORIGIN: str = "http://127.0.0.1:8081"
    SESSION_TTL_SECONDS: int = 900

    CALLBACK_URL: str = "https://YOURDOMAIN/api/callback"

    RP_ID: str = "cpunk.io"
    RP_NAME: str = "CPUNK"
    SCOPES: list[str] = ["login"]

    # -------------------------------------------------
    # Audit logging
    # -------------------------------------------------
    # Inside container we will mount ./audit -> /data/audit
    # so this default persists outside container when compose volume is set.
    AUDIT_LOG_PATH: str = "/data/audit/signature_audit.jsonl"

    class Config:
        env_file = ".env"

    @field_validator("ORIGIN")
    @classmethod
    def strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")

    @field_validator("RP_ID")
    @classmethod
    def normalize_rp_id(cls, v: str) -> str:
        """
        RP_ID must be domain-only (WebAuthn rpId semantics).
        Accepts accidental full URLs and strips scheme/path/trailing slashes.
        """
        v = (v or "").strip()

        # If someone passes a URL, extract hostname
        if "://" in v:
            p = urlparse(v)
            if p.hostname:
                v = p.hostname

        # Also handle "example.com/" accidental slash
        v = v.strip().rstrip("/").lower()
        return v


settings = Settings()
