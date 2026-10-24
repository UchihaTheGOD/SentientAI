"""Security Test Lab runs — persisted, non-destructive, for admin evidence.

Extended for Security Reports GUI (Phase 2/3): each run can store the
honest Sentinel assessment (Model A/B raw output + fusion) and links to
any incident / training candidate that was actually created.  Missing
values stay NULL and the UI shows "Unavailable"/"Not recorded" rather
than fabricating them.  New columns are nullable and auto-migrated via
app.database._add_missing_columns, so existing databases upgrade safely.
"""
from __future__ import annotations
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from app.database import Base

class SecurityLabRun(Base):
    __tablename__ = "security_lab_runs"
    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    created_by = Column(Integer, nullable=True, index=True)
    test_type = Column(String(40), nullable=False, index=True)
    target_url = Column(String(600), nullable=True)
    is_synthetic = Column(Boolean, default=False, nullable=False)
    status = Column(String(20), default="completed", nullable=False)  # completed / failed / not_detected
    correlation_ids = Column(Text, nullable=True)  # json list
    event_ids = Column(Text, nullable=True)  # json list
    request_count = Column(Integer, default=0)
    response_count = Column(Integer, default=0)
    http_statuses = Column(Text, nullable=True)  # json list
    detection_result = Column(String(20), nullable=True)  # detected / not_detected / synthetic / error
    error_message = Column(Text, nullable=True)
    meta_json = Column(Text, nullable=True)  # durations, labels
    completed_at = Column(DateTime, nullable=True)
    # --- Sentinel / Reports linkage (nullable; NULL = not assessed) --------
    model_a_text = Column(Text, nullable=True)
    model_a_status = Column(String(30), nullable=True)
    model_b_text = Column(Text, nullable=True)
    model_b_status = Column(String(30), nullable=True)
    agreement = Column(Boolean, nullable=True)
    fused_verdict = Column(String(30), nullable=True)  # likely_threat / needs_review / likely_benign / None
    fused_score = Column(Integer, nullable=True)
    fusion_json = Column(Text, nullable=True)  # full fuse_structured payload (bounded)
    incident_id = Column(Integer, ForeignKey("sentinel_incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    training_candidate_id = Column(Integer, ForeignKey("training_examples.id", ondelete="SET NULL"), nullable=True, index=True)
    analysis_error = Column(Text, nullable=True)
    analyzed_at = Column(DateTime, nullable=True)

