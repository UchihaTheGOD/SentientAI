"""Unused helper — kept for reference, not imported anywhere.

_collect_events was superseded by the inline event scan in
app/services/security_lab_runner.py. No module imports this file today
(grep for security_lab_run2 finds no imports), so it is safe to delete
once callers are confirmed absent.
"""
from __future__ import annotations
import json, time, uuid, urllib.parse
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models.security_lab import SecurityLabRun
from app.services.security_lab import _TEST_LOCK, validate_target_url, _local_origin, _synthetic_evidence, CANARYForType, _TEST_TYPES
def _collect_events(db: Session, ev_ids: list[int]) -> str:
    try:
        from app.models.attact_assessment import SecurityEvent
        rows = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(500).all()
        cutoff = datetime.now(timezone.utc).timestamp()-15
        seen = [r for r in rows if (r.created_at.timestamp() if getattr(r,"created_at",None) else 0) >= cutoff]
        for r in seen[:30]: ev_ids.append(r.id)
        has = any((r.event_type or "").startswith("suspicious_input") or (r.event_type or "")=="auth.login_failed" or (r.event_type or "").startswith("http.") for r in seen[:30])
        return ("detected" if has else "not_detected"), len(seen)
    except Exception as e:
        return "not_detected", 0
