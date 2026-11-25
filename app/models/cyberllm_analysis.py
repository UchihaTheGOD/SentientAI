"""CyberLLM per-call analysis records — aggregate-friendly analytics only.

One row per POST /api/cyberllm/analyze call. No log text, no raw model
output, and no user input is stored here: only the classification outcome
and timing, so the admin Security Dashboard can truthfully show CyberLLM
detection counts. Written best-effort after the response is built; a
failed write never breaks the analysis response.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String

from app.database import Base


class CyberLLMAnalysisEvent(Base):
    """One row per analyze call: outcome + timing, no content."""

    __tablename__ = "cyberllm_analysis_events"
    __table_args__ = (
        Index("ix_cyberllm_analysis_created", "created_at"),
        Index("ix_cyberllm_analysis_decision", "decision_source", "created_at"),
        Index("ix_cyberllm_analysis_class", "classification", "created_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    # log / http_request / url / vulnerability
    kind = Column(String(20), nullable=False)
    # likely_benign / needs_review / likely_threat, or None when the model
    # was unavailable and no classification was produced.
    classification = Column(String(20), nullable=True)
    # low / medium / high
    confidence = Column(String(10), nullable=True)
    # model / identity_rule / deterministic_override / evidence_mismatch /
    # truncated_output / unparseable_output / model_unavailable / model_error
    decision_source = Column(String(40), nullable=False)
    truncated = Column(Integer, default=0, nullable=False)  # 0/1
    latency_ms = Column(Integer, nullable=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
