"""Moderation models — user reports and the audit trail of admin actions.

PHASE 22: normal users can only *report*. Only admins act, and every action is
recorded in `ModerationAction` so the queue is auditable.
"""
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text

from app.database import Base

# What can be reported
REPORT_TARGETS = ("post", "comment", "profile")

# Why (kept short and fixed so the queue is filterable)
REPORT_REASONS = (
    "spam",
    "harassment",
    "inappropriate",
    "misinformation",
    "malicious",
    "other",
)
REPORT_REASON_LABELS = {
    "spam": "Spam or advertising",
    "harassment": "Harassment or abuse",
    "inappropriate": "Inappropriate content",
    "misinformation": "Misinformation",
    "malicious": "Malicious or harmful content",
    "other": "Something else",
}

# Queue lifecycle
REPORT_OPEN = "open"
REPORT_REVIEWING = "reviewing"
REPORT_RESOLVED = "resolved"
REPORT_DISMISSED = "dismissed"
REPORT_STATUSES = (REPORT_OPEN, REPORT_REVIEWING, REPORT_RESOLVED, REPORT_DISMISSED)

# Admin actions we record
MODERATION_ACTIONS = (
    "post_hidden",
    "post_restored",
    "post_removed",
    "comment_hidden",
    "comment_restored",
    "user_suspended",
    "user_reinstated",
    "report_resolved",
    "report_dismissed",
)


class Report(Base):
    """A user-submitted report about a post, comment, or profile."""

    __tablename__ = "reports"
    __table_args__ = (
        Index("ix_reports_target", "target_type", "target_id"),
        Index("ix_reports_status_created", "status", "created_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    reporter_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    target_type = Column(String(20), nullable=False)
    target_id = Column(Integer, nullable=False)
    target_label = Column(String(300), nullable=True)  # denormalised for the queue
    reason = Column(String(30), nullable=False)
    details = Column(Text, nullable=True)
    status = Column(String(20), default=REPORT_OPEN, nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    resolved_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolution_note = Column(Text, nullable=True)

    @property
    def reason_label(self) -> str:
        return REPORT_REASON_LABELS.get(self.reason, self.reason)

    @property
    def is_open(self) -> bool:
        return self.status in (REPORT_OPEN, REPORT_REVIEWING)


class ModerationAction(Base):
    """Immutable log of an administrative moderation decision."""

    __tablename__ = "moderation_actions"

    id = Column(Integer, primary_key=True, index=True)
    moderator_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action = Column(String(40), nullable=False, index=True)
    target_type = Column(String(20), nullable=False)
    target_id = Column(Integer, nullable=False)
    report_id = Column(Integer, ForeignKey("reports.id", ondelete="SET NULL"), nullable=True)
    reason = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    reverted = Column(Boolean, default=False, nullable=False)
