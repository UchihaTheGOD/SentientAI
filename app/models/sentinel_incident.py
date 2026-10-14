"""Sentinel incidents + temporary containment (Phase 5)."""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Index, ForeignKey
from app.database import Base

INCIDENT_STATUSES = ("pending_review","confirmed_threat","false_positive","inconclusive")
INCIDENT_STATUS_LABELS = {
    "pending_review":"Pending review",
    "confirmed_threat":"Confirmed threat",
    "false_positive":"False positive / benign",
    "inconclusive":"Inconclusive",
}

class SentinelIncident(Base):
    __tablename__ = "sentinel_incidents"
    __table_args__ = (
        Index("ix_sentinel_incidents_status_created","status","created_at"),
        Index("ix_sentinel_incidents_ip","ip_address"),
    )
    id = Column(Integer, primary_key=True, index=True)
    log_text = Column(Text, nullable=False)
    log_excerpt = Column(Text, nullable=True)  # truncated for display
    ip_address = Column(String(64), nullable=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    severity = Column(String(20), default="pending_review")
    status = Column(String(20), default="pending_review", nullable=False, index=True)
    fused_score = Column(Integer, nullable=True)
    fused_verdict = Column(String(30), nullable=True)
    model_a_text = Column(Text, nullable=True)
    model_b_text = Column(Text, nullable=True)
    model_a_status = Column(String(30), nullable=True)
    model_b_status = Column(String(30), nullable=True)
    agreement = Column(Boolean, nullable=True)
    evidence = Column(Text, nullable=True)  # json string of rules evidence
    prompt_snapshot = Column(Text, nullable=True)
    prompt_path = Column(String(300), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime, nullable=True)
    reviewer_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    review_note = Column(Text, nullable=True)
    # containment
    containment_type = Column(String(40), nullable=True)  # session_revoke | account_suspend | ip_temp_block
    containment_until = Column(DateTime, nullable=True)
    containment_active = Column(Boolean, default=False)
    containment_meta = Column(Text, nullable=True)

class TempBlock(Base):
    __tablename__ = "sentinel_temp_blocks"
    __table_args__ = (Index("ix_temp_blocks_active_until","active","expires_at"),)
    id = Column(Integer, primary_key=True, index=True)
    kind = Column(String(30), nullable=False)  # ip | account | session
    value = Column(String(200), nullable=False, index=True)  # ip string or user_id str
    reason = Column(String(300), nullable=True)
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False, index=True)
    active = Column(Boolean, default=True, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    revoked_by = Column(Integer, nullable=True)
    incident_id = Column(Integer, ForeignKey("sentinel_incidents.id", ondelete="SET NULL"), nullable=True)
