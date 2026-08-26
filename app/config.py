"""Application configuration loaded from environment variables."""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from project root
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


class Settings:
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-insecure-key-change-me")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./data/sentientai.db")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    ADMIN_SECRET: str = os.getenv("ADMIN_SECRET", "")
    CYBERLLM_API_URL: str = os.getenv("CYBERLLM_API_URL", "")
    CYBERLLM_API_KEY: str = os.getenv("CYBERLLM_API_KEY", "")


settings = Settings()
