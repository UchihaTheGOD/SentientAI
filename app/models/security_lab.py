"""Security Test Lab runs — persisted, non-destructive, for admin evidence."""
from __future__ import annotations
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean
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
    detection_result = Column(String(20), nullable=True)  # detected / not_detected / error
    error_message = Column(Text, nullable=True)
    meta_json = Column(Text, nullable=True)  # durations, labels
    completed_at = Column(DateTime, nullable=True)
