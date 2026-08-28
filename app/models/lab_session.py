"""LabSession model — tracks the lifecycle of a single lab test run.

Each time a tester opens a lab, a new session is created. Events generated
during the session are linked back to it. Sessions have a clear beginning
and end (completed, terminated, or expired).
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from app.database import Base


def _generate_session_id() -> str:
    """Generate a compact, URL-safe session identifier."""
    return uuid.uuid4().hex  # 32-char hex, no dashes


class LabSession(Base):
    __tablename__ = "lab_sessions"

    id = Column(Integer, primary_key=True, index=True)

    # Public-facing session identifier (used in URLs, never exposes internal id)
    session_id = Column(String(64), unique=True, nullable=False, index=True,
                        default=_generate_session_id)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    lab_id = Column(String(50), nullable=False, index=True)

    # Status lifecycle: active → completed / terminated / expired
    status = Column(String(20), nullable=False, default="active")

    started_at = Column(DateTime, nullable=False,
                        default=lambda: datetime.now(timezone.utc))
    ended_at = Column(DateTime, nullable=True)

    # Why the session ended (human-readable, not raw exception text)
    termination_reason = Column(Text, nullable=True)

    # Running counters — updated after each event
    attack_count = Column(Integer, default=0)
    detected_count = Column(Integer, default=0)
    blocked_count = Column(Integer, default=0)

    # Optional structured metadata (JSON string) — e.g. final severity summary
    metadata_json = Column(Text, nullable=True)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def is_active(self) -> bool:
        return self.status == "active"

    @property
    def duration_seconds(self) -> int | None:
        if self.started_at and self.ended_at:
            return int((self.ended_at - self.started_at).total_seconds())
        return None
