"""Internal audit + analytics models.

PHASE 31 separates two things that are easy to conflate:

  * `Activity` (app/models/activity.py) — USER-FACING. What a person sees on
    their own activity page and, when `is_public`, on their profile.
  * `AuditEvent` (here) — INTERNAL. An operations/security trail for admins.
    Never rendered on public pages.

Privacy rules baked in:
  * no passwords, tokens, cookies or raw credentials are ever written here;
  * IP addresses are stored only as a salted hash, so the trail is useful for
    "same client" correlation without retaining an identifier;
  * `detail` is a short human-readable string, not a request dump.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String, Text

from app.database import Base

# Audit event types (PHASE 31)
AUDIT_EVENT_TYPES = (
    "auth.login",
    "auth.login_failed",
    "auth.logout",
    "auth.register",
    "auth.password_changed",
    "post.created",
    "post.published",
    "post.updated",
    "post.archived",
    "post.deleted",
    "comment.created",
    "comment.deleted",
    "report.created",
    "moderation.action",
    "testing.session_started",
    "testing.session_ended",
    "testing.lab_completed",
    "analysis.generated",
    "analysis.feedback",
    "training.candidate_created",
    "training.candidate_approved",
    "training.candidate_rejected",
    "training.dataset_version_created",
    "training.evaluation_run",
    "checkpoint.registered",
    "checkpoint.status_changed",
)


class AuditEvent(Base):
    """Append-only internal event record."""

    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_type_created", "event_type", "created_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    actor_label = Column(String(100), nullable=True)  # username snapshot
    target_type = Column(String(40), nullable=True)
    target_id = Column(String(64), nullable=True)
    detail = Column(Text, nullable=True)
    ip_hash = Column(String(32), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


class DailyMetric(Base):
    """Aggregate counters keyed by (day, metric). No per-user data."""

    __tablename__ = "daily_metrics"
    __table_args__ = (
        Index("ix_daily_metric_day_name", "day", "metric", unique=True),
    )

    id = Column(Integer, primary_key=True, index=True)
    day = Column(String(10), nullable=False)  # YYYY-MM-DD
    metric = Column(String(60), nullable=False)
    value = Column(Integer, default=0, nullable=False)


class SearchQueryStat(Base):
    """Aggregate search term popularity — counts only, never linked to a user."""

    __tablename__ = "search_query_stats"

    id = Column(Integer, primary_key=True, index=True)
    term = Column(String(120), unique=True, nullable=False, index=True)
    count = Column(Integer, default=0, nullable=False)
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
