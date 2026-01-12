from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    ORIGIN: str = "cpunk.io"
    SESSION_TTL_SECONDS: int = 120
    # where the phone will POST
    CALLBACK_URL: str = "https://YOURDOMAIN/api/callback"

    class Config:
        env_file = ".env"

settings = Settings()
