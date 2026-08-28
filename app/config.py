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

    # Sentinel / CyberLLM model integration
    CYBERLLM_API_URL: str = os.getenv("CYBERLLM_API_URL", "")
    CYBERLLM_API_KEY: str = os.getenv("CYBERLLM_API_KEY", "")
    SENTINEL_MODEL_NAME: str = os.getenv("SENTINEL_MODEL_NAME", "SentinelSmolLM2-360M-V9")

    # Teacher API (external reviewer model)
    TEACHER_API_KEY: str = os.getenv("TEACHER_API_KEY", "")
    TEACHER_BASE_URL: str = os.getenv("TEACHER_BASE_URL", "")
    TEACHER_MODEL: str = os.getenv("TEACHER_MODEL", "")


settings = Settings()
