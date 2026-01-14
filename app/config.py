from urllib.parse import urlparse, urlunparse

from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    ORIGIN: str = "http://127.0.0.1:8081"
    SESSION_TTL_SECONDS: int = 900

    # where the phone will POST (optional / not used)
    CALLBACK_URL: str = "https://YOURDOMAIN/api/callback"

    # relying party / display
    RP_ID: str = "cpunk.io"
    RP_NAME: str = "CPUNK"

    # requested permissions (keep simple for now)
    SCOPES: list[str] = ["login"]

    # enforce origin↔rp_id relationship at config load time
    STRICT_RP_BINDING: bool = True

    class Config:
        env_file = ".env"

    @field_validator("ORIGIN")
    @classmethod
    def normalize_origin(cls, v: str) -> str:
        """
        ORIGIN must be an absolute http(s) origin reachable by the phone.

        Normalization:
          - strip whitespace
          - strip trailing slash
          - require http/https
          - require hostname
          - lowercase hostname

        Note: we preserve an optional port if present.
        """
        v = (v or "").strip().rstrip("/")
        p = urlparse(v)

        if p.scheme not in ("http", "https"):
            raise ValueError("ORIGIN must start with http:// or https://")

        if not p.hostname:
            raise ValueError("ORIGIN must include a hostname")

        # Normalize host casing; keep port if present; drop username/password/query/fragment
        netloc = p.hostname.lower()
        if p.port:
            netloc = f"{netloc}:{p.port}"

        normalized = urlunparse((p.scheme, netloc, "", "", "", ""))
        return normalized

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

        v = v.strip().rstrip("/").lower()

        if not v:
            raise ValueError("RP_ID cannot be empty")

        # RP_ID must not contain scheme/path
        if "/" in v or ":" in v:
            # ":" would indicate a port; WebAuthn rpId must not include it
            raise ValueError("RP_ID must be a bare domain (no scheme, no port, no path)")

        return v

    @field_validator("STRICT_RP_BINDING")
    @classmethod
    def normalize_strict(cls, v):
        # accept 0/1, "true"/"false" from env consistently
        if isinstance(v, bool):
            return v
        if isinstance(v, (int,)):
            return bool(v)
        if isinstance(v, str):
            return v.strip().lower() not in ("0", "false", "no", "off", "")
        return True

    @field_validator("RP_NAME")
    @classmethod
    def normalize_rp_name(cls, v: str) -> str:
        return (v or "").strip() or "CPUNK"

    @field_validator("SCOPES")
    @classmethod
    def normalize_scopes(cls, v):
        # ensure list[str] even if someone sets SCOPES="login,admin"
        if isinstance(v, str):
            parts = [p.strip() for p in v.split(",") if p.strip()]
            return parts or ["login"]
        return v


settings = Settings()

# -----------------------------------------------------------------------------
# Cross-field validation (Origin ↔ RP binding)
# -----------------------------------------------------------------------------
# WebAuthn-like expectation:
#   origin host must equal rp_id or be a subdomain of rp_id.
#
# For tunnel dev:
#   set RP_ID to the tunnel hostname.
try:
    origin_host = urlparse(settings.ORIGIN).hostname or ""
    rp_id = settings.RP_ID

    if settings.STRICT_RP_BINDING:
        ok = (origin_host == rp_id) or origin_host.endswith("." + rp_id)
        if not ok:
            raise ValueError(
                f"ORIGIN host '{origin_host}' does not match RP_ID '{rp_id}'. "
                f"Set RP_ID to the ORIGIN hostname (tunnel) or use a cpunk.io subdomain for ORIGIN."
            )
except Exception as e:
    # Fail fast at import time to prevent emitting bad QR payloads
    raise
