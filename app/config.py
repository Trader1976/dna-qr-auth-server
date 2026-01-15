from urllib.parse import urlparse
from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    ORIGIN: str = "http://127.0.0.1:8081"
    SESSION_TTL_SECONDS: int = 900

    CALLBACK_URL: str = "https://YOURDOMAIN/api/callback"

    #choose which version to use
    # v3 = stateful
    # v4 = stateless
    # auto (prefer v4, fallback v3)
    AUTH_MODE: str = "auto"  # "v3" | "v4" | "auto"

    RP_ID: str = "cpunk.io"
    RP_NAME: str = "CPUNK"
    SCOPES: list[str] = ["login"]

    # v4 server signing key (Ed25519 private key, raw 32 bytes, base64-encoded)
    SERVER_ED25519_SK_B64: str

    # -------------------------------------------------
    # Audit logging
    # -------------------------------------------------
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
        v = (v or "").strip()
        if "://" in v:
            p = urlparse(v)
            if p.hostname:
                v = p.hostname
        return v.strip().rstrip("/").lower()


    @field_validator("AUTH_MODE")
    @classmethod
    def normalize_auth_mode(cls, v: str) -> str:
        v = (v or "auto").strip().lower()
        if v not in ("auto", "v3", "v4"):
            raise ValueError("AUTH_MODE must be one of: auto, v3, v4")
        return v

settings = Settings()

