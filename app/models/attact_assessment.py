"""ATTACT assessments + findings persistence (spec section 8).

Non-destructive schema: Base.metadata.create_all creates tables if missing;
existing installs pick them up via _add_missing_columns.
"""
from __future__ import annotations
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Index, ForeignKey

from app.database import Base


class AttactAssessment(Base):
    __tablename__ = "attact_assessments"
    __table_args__ = (
        Index("ix_attact_assess_target_created", "target", "created_at"),
        Index("ix_attact_assess_run_id", "run_id", unique=True),
        Index("ix_attact_assess_status_created", "status", "created_at"),
    )
    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(32), nullable=False, unique=True, index=True)
    target = Column(String(500), nullable=False)
    timestamp = Column(String(40), nullable=True)  # ISO from report
    checks_requested = Column(Text, nullable=True)  # json list
    checks_executed = Column(Text, nullable=True)   # json list (actual)
    request_count = Column(Integer, default=0)
    elapsed_ms = Column(Integer, default=0)
    status = Column(String(20), default="completed", nullable=False, index=True)  # completed/partial_failed/error
    allowlist = Column(Text, nullable=True)  # json list
    limitations = Column(Text, nullable=True)  # json list
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    finished_at = Column(DateTime, nullable=True)
    # full report dict for export / dedup; bounded
    report_json = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    # correlation to incident if one was opened from this run
    incident_id = Column(Integer, ForeignKey("sentinel_incidents.id", ondelete="SET NULL"), nullable=True)


class AttactFinding(Base):
    __tablename__ = "attact_findings"
    __table_args__ = (
        Index("ix_attact_finding_assessment", "assessment_id"),
        Index("ix_attact_finding_check_status", "check_name", "status"),
        Index("ix_attact_finding_severity", "severity"),
    )
    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("attact_assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    check_name = Column(String(60), nullable=False, index=True)
    title = Column(String(300), nullable=False)
    status = Column(String(20), nullable=False, index=True)  # confirmed/potential/not_found/not_run
    severity = Column(String(20), nullable=False)
    confidence = Column(String(20), nullable=False)
    summary = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)  # redacted, capped
    remediation = Column(Text, nullable=True)
    request_count = Column(Integer, default=0)
    meta_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    # admin triage per finding
    triage_status = Column(String(20), default="open", nullable=False)  # open/fixed/false_positive
    triage_note = Column(Text, nullable=True)
    triage_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    triage_at = Column(DateTime, nullable=True)
    # optional link to incident for this finding
    incident_id = Column(Integer, ForeignKey("sentinel_incidents.id", ondelete="SET NULL"), nullable=True)


class SecurityEvent(Base):
    """Central security-event log — one row per notable request or scan finding.

    Redacted at write time; evidence never stores passwords/tokens/cookies/raw bodies.
    Indexed for dashboard filters.
    """
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_sec_event_created", "created_at"),
        Index("ix_sec_event_category_severity", "category", "severity"),
        Index("ix_sec_event_source", "source"),
        Index("ix_sec_event_ip", "ip_address"),
        Index("ix_sec_event_user", "user_id"),
        Index("ix_sec_event_assessment", "assessment_id"),
        Index("ix_sec_event_incident", "incident_id"),
        Index("ix_sec_event_correlation", "correlation_id"),
    )
    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    correlation_id = Column(String(36), nullable=True, index=True)
    event_type = Column(String(80), nullable=False)  # e.g. attact.finding, auth.login_failed
    category = Column(String(60), nullable=True)
    severity = Column(String(20), nullable=True)
    confidence = Column(String(20), nullable=True)
    source = Column(String(40), nullable=True)  # attact / rule / model_a / model_b / fusion
    ip_address = Column(String(64), nullable=True, index=True)
    ip_hash = Column(String(64), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    session_digest = Column(String(32), nullable=True)
    user_agent = Column(String(300), nullable=True)
    route = Column(String(300), nullable=True)
    method = Column(String(10), nullable=True)
    http_status = Column(Integer, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    assessment_id = Column(Integer, ForeignKey("attact_assessments.id", ondelete="SET NULL"), nullable=True)
    incident_id = Column(Integer, ForeignKey("sentinel_incidents.id", ondelete="SET NULL"), nullable=True)
    enforcement_action = Column(String(40), nullable=True)
    enforcement_reason = Column(String(300), nullable=True)
    evidence = Column(Text, nullable=True)  # redacted, capped
    meta_json = Column(Text, nullable=True)
