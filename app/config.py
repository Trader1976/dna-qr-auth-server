from pydantic_settings import BaseSettings
from pydantic import field_validator

class Settings(BaseSettings):
    ORIGIN: str = "http://127.0.0.1:8081"
    SESSION_TTL_SECONDS: int = 900

    # where the phone will POST (optional, you aren't using it yet in main.py)
    CALLBACK_URL: str = "https://YOURDOMAIN/api/callback"

    # relying party / display
    RP_ID: str = "cpunk.io"
    RP_NAME: str = "CPUNK"

    # requested permissions (keep simple for now)
    SCOPES: list[str] = ["login"]

    class Config:
        env_file = ".env"

    @field_validator("ORIGIN")
    @classmethod
    def strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")

settings = Settings()
