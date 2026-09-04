"""Application configuration loaded from environment variables."""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# Insecure signing key used ONLY in development when SECRET_KEY is unset. In
# production a missing key is fatal (see Settings.__init__) — silently minting a
# fresh random key each boot would invalidate every issued token on restart and
# quietly mask a real misconfiguration.
_INSECURE_DEV_SECRET = "dev-insecure-key-change-me"


def _as_bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


class Settings:
    def __init__(self) -> None:
        self.ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

        secret = os.getenv("SECRET_KEY", "").strip()
        if not secret:
            if self.ENVIRONMENT == "production":
                raise RuntimeError(
                    "SECRET_KEY is required in production. Set it in the "
                    "environment — refusing to start with an insecure default."
                )
            secret = _INSECURE_DEV_SECRET
        self.SECRET_KEY: str = secret

        self.DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./app.db")
        self.ALGORITHM: str = "HS256"
        self.ACCESS_TOKEN_EXPIRE_MINUTES: int = int(
            os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")
        )

        # Password-reset tokens: short-lived and single-use (services/password_reset.py).
        self.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = int(
            os.getenv("PASSWORD_RESET_TOKEN_EXPIRE_MINUTES", "30")
        )

        # Outbound email for password reset — provider-agnostic SMTP. Nothing is
        # hardcoded; a blank SMTP_HOST makes the mailer log the link instead of
        # sending (dev). Credentials live in the environment, never in the DB.
        self.SMTP_HOST: str = os.getenv("SMTP_HOST", "")
        self.SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
        self.SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "")
        self.SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
        self.SMTP_FROM: str = os.getenv("SMTP_FROM", "")
        self.SMTP_USE_TLS: bool = _as_bool(os.getenv("SMTP_USE_TLS", "true"))

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"


settings = Settings()
