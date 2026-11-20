"""AI Automation Center — persistent analysis queue.

Two tables, both additive and backward compatible:

* ``automation_jobs`` — one row per security event that enters the
  automation pipeline. It is the durable record of the whole chain:
  event -> AI assessment -> incident -> training example. The row is
  created when the event is logged (see ``log_event``) and updated by
  the background worker; it is never deleted by the pipeline, so the
  audit trail survives worker restarts, failures and retries.
* ``automation_settings`` — a single row (id=1) holding the automation
  switch and the worker tuning. The worker thread is started only when
  ``enabled`` is true; queueing itself is independent of the switch so
  a paused pipeline still shows its backlog honestly.

No existing table is altered. No existing row is touched by this module.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)

from app.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class AutomationJob(Base):
    """One queued AI analysis for one security event.

    Statuses: ``pending`` (waiting, including scheduled auto-retry),
    ``processing`` (claimed by the worker), ``completed`` (assessed),
    ``failed`` (retries exhausted; needs a manual retry).

    ``verdict`` is the fused verdict (likely_benign / needs_review /
    likely_threat) or NULL when the event carried no analyzable text.
    ``mitre_technique`` is intentionally NULL in this version: the
    CyberLLMv1 classifier emits no MITRE technique IDs by design, and
    this pipeline never invents one. The column exists so a future,
    verified technique source can fill it without another migration.
    """

    __tablename__ = "automation_jobs"
    __table_args__ = (
        Index("ix_automation_jobs_event", "event_id"),
        Index("ix_automation_jobs_status", "status"),
        Index("ix_automation_jobs_created", "created_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(
        Integer,
        ForeignKey("security_events.id", ondelete="SET NULL"),
        nullable=True,
        unique=True,
        index=True,
    )
    status = Column(String(20), default="pending", nullable=False)
    attempts = Column(Integer, default=0, nullable=False)
    max_attempts = Column(Integer, default=3, nullable=False)
    next_attempt_at = Column(DateTime, nullable=True)

    # Structured AI assessment (NULL until the job completes).
    verdict = Column(String(20), nullable=True)
    fused_score = Column(Integer, nullable=True)
    confidence = Column(String(20), nullable=True)
    severity = Column(String(20), nullable=True)
    explanation = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    recommended_action = Column(Text, nullable=True)
    mitre_technique = Column(String(40), nullable=True)
    decision_source = Column(String(40), nullable=True)
    assessment_json = Column(Text, nullable=True)

    # AI Review linkage and the reason a job did NOT produce a candidate.
    review_exclusion_reason = Column(String(60), nullable=True)
    incident_id = Column(
        Integer,
        ForeignKey("sentinel_incidents.id", ondelete="SET NULL"),
        nullable=True,
    )
    incident_outcome = Column(String(20), nullable=True)  # created/linked/none
    training_example_id = Column(
        Integer,
        ForeignKey("training_examples.id", ondelete="SET NULL"),
        nullable=True,
    )

    error_message = Column(Text, nullable=True)
    latency_ms = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=_utcnow, index=True)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        def _iso(value):
            return value.isoformat() if value is not None else None

        return {
            "id": self.id,
            "event_id": self.event_id,
            "status": self.status,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "next_attempt_at": _iso(self.next_attempt_at),
            "verdict": self.verdict,
            "fused_score": self.fused_score,
            "confidence": self.confidence,
            "severity": self.severity,
            "explanation": self.explanation,
            "evidence": self.evidence,
            "recommended_action": self.recommended_action,
            "mitre_technique": self.mitre_technique,
            "decision_source": self.decision_source,
            "review_exclusion_reason": self.review_exclusion_reason,
            "incident_id": self.incident_id,
            "incident_outcome": self.incident_outcome,
            "training_example_id": self.training_example_id,
            "error_message": self.error_message,
            "latency_ms": self.latency_ms,
            "created_at": _iso(self.created_at),
            "updated_at": _iso(self.updated_at),
            "started_at": _iso(self.started_at),
            "completed_at": _iso(self.completed_at),
        }


class AutomationSettings(Base):
    """Single-row switch + tuning for the automation worker (id=1)."""

    __tablename__ = "automation_settings"

    id = Column(Integer, primary_key=True)
    enabled = Column(Boolean, default=False, nullable=False)
    poll_interval_seconds = Column(Integer, default=5, nullable=False)
    max_attempts = Column(Integer, default=3, nullable=False)
    backoff_base_seconds = Column(Integer, default=30, nullable=False)
    worker_last_seen_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
