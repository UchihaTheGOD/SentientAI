"""Input validation for security-log text.

Moved verbatim from the obsolete Sentinel prompt service: these limits
are application input validation, not model-specific prompt logic.
CyberLLMv1 and the security-analysis routes both use them, so they
live here instead of in a prompt module tied to a retired model.
"""
from __future__ import annotations

MAX_LOG_CHARS = 8000


def validate_log_text(raw: str | None) -> str:
    """Clean and validate log text input."""
    if not raw or not raw.strip():
        raise ValueError("log_text is required")
    cleaned = raw.replace("\x00", "").strip()
    if len(cleaned) > MAX_LOG_CHARS:
        raise ValueError(f"log_text exceeds {MAX_LOG_CHARS} characters")
    if len(cleaned) < 1:
        raise ValueError("log_text is required")
    return cleaned
