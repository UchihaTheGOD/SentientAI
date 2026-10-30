"""Bridge: security_events / ATTACT findings -> CyberLLMv1 classification + rules -> SentinelIncident -> sanitized TrainingExample.

Preserves deterministic security_events logging. Classification is failure-isolated:
  - missing model / timeout / empty -> still returns fusion from rules, persists
    incident with accurate model statuses, never treats absent model as success.
  - logging of the original event always succeeds even if this bridge fails.

Dedup/idempotency:
  - idempotency: if SecurityEvent.incident_id or AttactFinding.incident_id is already set,
    return the existing incident without re-running inference.
  - dedup: hash(ip + log_head) within 10-min window via containment_meta marker.

Training collection:
  - eligible incidents (needs_review / likely_threat or score >= threshold)
    are forwarded to app.services.collection.collect_from_incident which
    redacts, truncates, dedups, scores advisory-only, and writes a
    CANDIDATE with safe_to_train=False.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.attact_assessment import AttactAssessment, AttactFinding, SecurityEvent
from app.models.sentinel_incident import SentinelIncident

logger = logging.getLogger("sentientai.sentinel_bridge")

DEDUP_WINDOW_MIN = 10
BENIGN_SCORE_THRESHOLD = 35
MAX_LOG_FOR_BRIDGE = 8000


def _dedup_key(ip: str | None, log_text: str) -> str:
    head = (log_text or "")[:600].strip().lower()
    return hashlib.sha256(f"{ip or ''}:{head}".encode("utf-8")).hexdigest()[:24]


def _find_recent_duplicate(db: Session, key: str, window_min: int = DEDUP_WINDOW_MIN) -> Optional[SentinelIncident]:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_min)
    try:
        rows = db.query(SentinelIncident).filter(SentinelIncident.created_at >= cutoff).all()
        for r in rows:
            meta = r.containment_meta or ""
            if key in meta:
                return r
    except Exception:
        return None
    return None


def _event_log_text(event: SecurityEvent) -> str:
    parts = []
    if event.event_type:
        parts.append(event.event_type)
    if event.category:
        parts.append(f"category={event.category}")
    if event.route:
        parts.append(f"route={event.route}")
    if event.method:
        parts.append(f"method={event.method}")
    if event.evidence:
        parts.append(str(event.evidence)[:2000])
    if event.meta_json:
        try:
            meta = json.loads(event.meta_json)
            if isinstance(meta, dict):
                parts.append(json.dumps({k: str(v)[:300] for k, v in list(meta.items())[:5]}, ensure_ascii=False))
        except Exception:
            pass
    text = " | ".join(p for p in parts if p)
    return text[:MAX_LOG_FOR_BRIDGE] if text else (event.evidence or event.event_type or "")[:MAX_LOG_FOR_BRIDGE]


def _finding_log_text(finding: AttactFinding, assessment: Optional[AttactAssessment] = None) -> str:
    parts = []
    parts.append(f"check={finding.check_name}")
    parts.append(f"title={finding.title}")
    if finding.summary:
        parts.append(str(finding.summary)[:1500])
    if finding.evidence:
        parts.append(str(finding.evidence)[:2000])
    if finding.severity:
        parts.append(f"severity={finding.severity}")
    if finding.confidence:
        parts.append(f"confidence={finding.confidence}")
    if assessment and assessment.target:
        parts.append(f"target={assessment.target}")
    text = " | ".join(p for p in parts if p)
    return text[:MAX_LOG_FOR_BRIDGE]


def _run_analysis(log_text: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Run CyberLLMv1 classification + deterministic rules fusion. Never raises; returns honest statuses.

    Returns (classification, fused, structured) where classification is the
    single CyberLLMv1 result (status ok/unavailable/unparseable) and fused
    is the rules+model fusion. When the model is unavailable, fused is
    rules-only — never a fabricated model verdict.
    """
    from app.services.classifier import classify_log, fuse_classification

    try:
        classification = classify_log(log_text)
    except Exception as exc:
        logger.exception("classification failed: %s", exc)
        classification = {
            "source": "cyberllm", "status": "unavailable", "classification": "needs_review",
            "model_classification": None, "confidence": "low", "summary": "",
            "indicators": [], "reasoning": [], "limitations": [str(exc)[:300]],
            "deterministic_findings": [], "parse_ok": False, "truncated": False,
            "output_tokens": 0, "latency_ms": 0, "raw_output": "", "error": str(exc),
        }
    try:
        fused = fuse_classification(log_text, classification)
    except Exception as exc:
        logger.warning("fusion failed: %s", exc)
        fused = {"fused_score": 50, "fused_verdict": "needs_review",
                 "rules": {"evidence": [str(exc)[:300]], "score": 50, "verdict": "needs_review"}, "components": []}
    structured = {
        "fused_verdict": fused.get("fused_verdict"), "fused_score": fused.get("fused_score"),
        "rules": fused.get("rules"), "classification": classification, "components": fused.get("components"),
    }
    return classification, fused, structured


def _maybe_collect_training(db: Session, incident: SentinelIncident, actor_id: Optional[int] = None):
    try:
        verdict = (incident.fused_verdict or "").strip().lower()
        score = int(incident.fused_score or 0)
        eligible = verdict in ("likely_threat", "needs_review") or score >= BENIGN_SCORE_THRESHOLD
        if not eligible:
            return None
        from app.services.collection import collect_from_incident
        actor = None
        if actor_id is not None:
            try:
                from app.models.user import User
                actor = db.query(User).filter(User.id == actor_id).first()
            except Exception:
                actor = None
        return collect_from_incident(db, incident, actor=actor, request=None)
    except Exception as exc:
        logger.warning("training collection from incident %s failed: %s", getattr(incident, "id", "?"), exc)
        return None


def submit_security_event_for_analysis(db, *, event_id, triggered_by=None, request=None):
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if event is None:
        raise ValueError(f"SecurityEvent {event_id} not found")
    if event.incident_id is not None:
        inc = db.query(SentinelIncident).filter(SentinelIncident.id == event.incident_id).first()
        if inc is not None:
            return {"incident": inc, "is_duplicate": True, "reason": "already_linked", "dedup_key": None, "fused": {"fused_verdict": inc.fused_verdict, "fused_score": inc.fused_score}}
    log_text = _event_log_text(event)
    if not log_text or not log_text.strip():
        return {"incident": None, "is_duplicate": False, "reason": "empty_log_text", "fused": None}
    from app.services.security_events import redact
    redacted_head = redact(log_text) or log_text
    key = _dedup_key(event.ip_address, redacted_head)
    dup = _find_recent_duplicate(db, key)
    if dup is not None:
        try:
            event.incident_id = dup.id
            db.commit()
        except Exception:
            db.rollback()
        return {"incident": dup, "is_duplicate": True, "reason": "dedup_window", "dedup_key": key, "fused": {"fused_verdict": dup.fused_verdict, "fused_score": dup.fused_score}}
    inference, fused, structured = _run_analysis(redacted_head)
    verdict = (fused.get("fused_verdict") or "").lower()
    score = int(fused.get("fused_score") or 0)
    _is_suspicious_event = (event.event_type or "").startswith("suspicious_input") or (event.event_type or "").startswith("attact.") or (event.category or "") in ("sqli","xss","traversal","auth","access","csrf","methods","rate-limit","headers-cookies","info-disclosure","unknown")
    # http.200/ benign category with no suspicious prefix should remain benign-suppressible
    # Only suppress benign if not a suspicious event; suspicious probes must still create an incident for human review
    if verdict == "likely_benign" and score < BENIGN_SCORE_THRESHOLD and not _is_suspicious_event:
        return {"incident": None, "is_duplicate": False, "reason": "benign_no_incident", "dedup_key": key, "fused": fused, "inference": inference, "structured": structured}
    # For suspicious events, ensure at least needs_review so an incident is created (rules alone may be auth-centric)
    if _is_suspicious_event and verdict == "likely_benign" and score < BENIGN_SCORE_THRESHOLD:
        fused = dict(fused)
        fused["fused_verdict"] = "needs_review"
        fused["fused_score"] = max(int(fused.get("fused_score") or 0), 35)
        if isinstance(fused.get("rules"), dict):
            try:
                fused["rules"] = dict(fused["rules"])
                fused["rules"]["verdict"] = "needs_review"
                fused["rules"]["score"] = max(int(fused["rules"].get("score") or 0), 35)
            except Exception:
                pass
    from app.services.incident_service import create_incident
    ip = event.ip_address
    # The dedup key must be persisted atomically with creation: the
    # old code set containment_meta only in the link block below, so
    # a link failure left a committed incident with no key, and the
    # next submission could not dedup against it and duplicated it.
    _meta = json.dumps({"dedup_key": key, "source_event_id": event.id, "triggered_by": triggered_by}, ensure_ascii=False)
    try:
        incident = create_incident(db, log_text=redacted_head[:8000], ip_address=ip, fused=fused, classification=inference, containment_meta=_meta)
    except Exception as exc:
        logger.exception("create_incident failed for event %s: %s", event_id, exc)
        raise
    try:
        event.incident_id = incident.id
        if event.assessment_id is not None:
            try:
                q = db.query(AttactFinding).filter(AttactFinding.assessment_id == event.assessment_id, AttactFinding.incident_id.is_(None))
                cand = None
                if event.category:
                    cand = q.filter(AttactFinding.check_name == event.category).first()
                    if cand is None:
                        cand = q.first()
                else:
                    cand = q.first()
                if cand is not None:
                    cand.incident_id = incident.id
            except Exception as exc2:
                logger.warning("link finding from event failed: %s", exc2)
        db.commit()
        db.refresh(incident)
        db.refresh(event)
    except Exception as exc:
        logger.exception("linking incident to event failed: %s", exc)
        try:
            db.rollback()
        except Exception:
            pass
    te = _maybe_collect_training(db, incident, actor_id=triggered_by)
    return {"incident": incident, "is_duplicate": False, "reason": "created", "dedup_key": key, "fused": fused, "inference": inference, "structured": structured, "training_example_id": getattr(te, "id", None)}

def submit_attact_finding_for_analysis(db, *, finding_id, triggered_by=None, request=None):
    finding = db.query(AttactFinding).filter(AttactFinding.id == finding_id).first()
    if finding is None:
        raise ValueError(f"AttactFinding {finding_id} not found")
    if finding.incident_id is not None:
        inc = db.query(SentinelIncident).filter(SentinelIncident.id == finding.incident_id).first()
        if inc is not None:
            return {"incident": inc, "is_duplicate": True, "reason": "already_linked", "dedup_key": None, "fused": {"fused_verdict": inc.fused_verdict, "fused_score": inc.fused_score}}
    assessment = None
    if finding.assessment_id is not None:
        assessment = db.query(AttactAssessment).filter(AttactAssessment.id == finding.assessment_id).first()
    log_text = _finding_log_text(finding, assessment)
    from app.services.security_events import redact
    redacted = redact(log_text) or log_text
    ip = None
    related_event = None
    try:
        if assessment is not None:
            q = db.query(SecurityEvent).filter(SecurityEvent.assessment_id == assessment.id)
            cand = q.filter(SecurityEvent.category == finding.check_name).first()
            if cand is None:
                cand = q.first()
            related_event = cand
            if related_event and related_event.ip_address:
                ip = related_event.ip_address
    except Exception:
        pass
    key = _dedup_key(ip, redacted)
    dup = _find_recent_duplicate(db, key)
    if dup is not None:
        try:
            finding.incident_id = dup.id
            if assessment is not None and assessment.incident_id is None:
                assessment.incident_id = dup.id
            if related_event is not None and related_event.incident_id is None:
                related_event.incident_id = dup.id
            db.commit()
        except Exception:
            db.rollback()
        return {"incident": dup, "is_duplicate": True, "reason": "dedup_window", "dedup_key": key, "fused": {"fused_verdict": dup.fused_verdict, "fused_score": dup.fused_score}}
    inference, fused, structured = _run_analysis(redacted)
    verdict = (fused.get("fused_verdict") or "").lower()
    score = int(fused.get("fused_score") or 0)
    _is_confirmed_finding = (finding.status or "") in ("confirmed", "potential")
    if verdict == "likely_benign" and score < BENIGN_SCORE_THRESHOLD and not _is_confirmed_finding:
        return {"incident": None, "is_duplicate": False, "reason": "benign_no_incident", "dedup_key": key, "fused": fused, "inference": inference, "structured": structured}
    if _is_confirmed_finding and verdict == "likely_benign" and score < BENIGN_SCORE_THRESHOLD:
        fused = dict(fused)
        fused["fused_verdict"] = "needs_review"
        fused["fused_score"] = max(int(fused.get("fused_score") or 0), 40)
        if isinstance(fused.get("rules"), dict):
            try:
                fused["rules"] = dict(fused["rules"])
                fused["rules"]["verdict"] = "needs_review"
                fused["rules"]["score"] = max(int(fused["rules"].get("score") or 0), 40)
            except Exception:
                pass
    from app.services.incident_service import create_incident
    # Dedup key persisted atomically with creation (see the event
    # path above): a link failure must not leave a keyless incident
    # that a retry cannot dedup against.
    _meta = json.dumps({"dedup_key": key, "source_finding_id": finding.id, "source_assessment_id": getattr(assessment, "id", None), "triggered_by": triggered_by}, ensure_ascii=False)
    try:
        incident = create_incident(db, log_text=redacted[:8000], ip_address=ip, fused=fused, classification=inference, containment_meta=_meta)
    except Exception as exc:
        logger.exception("create_incident failed for finding %s: %s", finding_id, exc)
        raise
    try:
        finding.incident_id = incident.id
        if assessment is not None and assessment.incident_id is None:
            assessment.incident_id = incident.id
        if related_event is not None and related_event.incident_id is None:
            related_event.incident_id = incident.id
        if related_event is None:
            try:
                from app.services.security_events import log_event as _log_event
                _log_event(db, event_type="attact.finding", category=finding.check_name, severity=finding.severity, confidence=finding.confidence, source="attact", ip_address=ip, assessment_id=getattr(assessment, "id", None), incident_id=incident.id, evidence=redacted[:2000], meta={"finding_id": finding.id, "check": finding.check_name, "via": "sentinel_bridge"})
            except Exception as e2:
                logger.warning("auto-create security_event for finding failed: %s", e2)
        db.commit()
        db.refresh(incident)
        db.refresh(finding)
        if assessment is not None:
            try:
                db.refresh(assessment)
            except Exception:
                pass
    except Exception as exc:
        logger.exception("linking incident to finding failed: %s", exc)
        try:
            db.rollback()
        except Exception:
            pass
    te = _maybe_collect_training(db, incident, actor_id=triggered_by)
    return {"incident": incident, "is_duplicate": False, "reason": "created", "dedup_key": key, "fused": fused, "inference": inference, "structured": structured, "training_example_id": getattr(te, "id", None)}
