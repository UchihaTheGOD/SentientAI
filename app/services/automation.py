"""AI Automation Center — persistent queue + background worker.

Design (no new infrastructure, by deliberate choice):

* The queue is the ``automation_jobs`` table in the existing SQLite
  database. SQLite already backs every other pipeline here, the worker
  is a single in-process thread, and the job volume is one row per
  security event — Redis/Celery would add a deployment dependency for
  no capability this workload needs. If a future deployment runs
  several backend processes, the claim step (UPDATE ... WHERE
  status='pending') must be hardened before enabling a second worker.
* Event ingestion never blocks on the model. ``log_event`` only
  inserts a pending job row; all inference happens in the worker.
* The worker processes jobs strictly one at a time, so the single
  Qwen3-1.7B + LoRA model is loaded once (lazily, by the existing
  loader) and never re-loaded per event, and GPU memory sees at most
  one inference at a time.
* Model-unavailable is a *retryable* failure: the job stays queued
  with backoff instead of being completed with a rules-only verdict,
  because a rules-only result is not an AI assessment and must not be
  presented as one. After ``max_attempts`` the job lands in ``failed``
  for a manual retry once the model is back.
* Incident creation is idempotent: an already-linked event, a recent
  incident with the same bridge dedup key, or an automation-created
  incident already recorded for this event (window-free recovery for
  a crash between incident commit and link persistence, R2) is linked
  instead of duplicated (audit D1, for this pipeline).
* Training candidacy reuses the bridge eligibility gate (verdict
  likely_threat/needs_review, or score >= 35) and additionally
  requires a parseable model output. A candidate is never training
  data: it is a TrainingExample with status ``candidate`` and
  ``safe_to_train=False`` until a human approves it.
* The model never sees a new prompt surface: analysis is exactly
  ``classify_log`` + ``fuse_classification`` with the frozen
  templates, so untrusted log text is input data exactly as in the
  existing manual analyze paths, and no AI verdict triggers any
  blocking, remediation or auto-approval.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy.exc import IntegrityError
from sqlalchemy import func

from app.database import SessionLocal
from app.models.attact_assessment import SecurityEvent
from app.models.automation import AutomationJob, AutomationSettings
from app.services.classifier import classify_log, fuse_classification
from app.services.collection import collect_from_incident
from app.services.incident_service import create_incident
from app.services.sentinel_bridge import (
    BENIGN_SCORE_THRESHOLD,
    _dedup_key,
    _event_log_text,
    _find_recent_duplicate,
)

logger = logging.getLogger(__name__)

MAX_EXPLANATION_CHARS = 2000
MAX_EVIDENCE_CHARS = 2000
MAX_ASSESSMENT_CHARS = 8000
MAX_ERROR_CHARS = 2000

_SUSPICIOUS_CATEGORIES = (
    "sqli", "xss", "traversal", "auth", "access", "csrf", "methods",
    "rate-limit", "headers-cookies", "info-disclosure", "unknown",
)
_SEVERITY_BY_VERDICT = {
    "likely_threat": "high",
    "needs_review": "medium",
    "likely_benign": "low",
}


class RetryableError(Exception):
    """A processing failure worth retrying (usually: model unavailable)."""


def _utcnow_naive() -> datetime:
    """Naive UTC now — matches how SQLite round-trips datetimes here.

    Stored datetimes come back naive, so all queue-time comparisons
    use naive UTC on both sides and never mix aware/naive values.
    """

    return datetime.now(timezone.utc).replace(tzinfo=None)


def is_review_eligible(verdict: str | None, score: int | None) -> bool:
    """Bridge eligibility gate, shared with the sentinel analyze path."""

    return verdict in ("likely_threat", "needs_review") or (
        score is not None and score >= BENIGN_SCORE_THRESHOLD
    )


def _is_suspicious_event(event: SecurityEvent) -> bool:
    """Mirror of the bridge predicate: suspicious by construction."""

    return (
        (event.event_type or "").startswith("suspicious_input")
        or (event.event_type or "").startswith("attact.")
        or (event.category or "") in _SUSPICIOUS_CATEGORIES
    )


def _find_automation_incident_for_event(db, event_id: int):
    """Find an incident this pipeline already created for one event.

    Automation-created incidents record ``source_event_id`` in their
    containment_meta. This lookup is window-free: it is the recovery
    path for a crash between ``create_incident``'s internal commit and
    the job's final commit, where the event link was lost and the
    10-minute bridge dedup window may since have expired (R2). Only
    automation-created incidents match — the ``triggered_by`` check
    excludes manual bridge incidents, which carry a user id there, and
    the int equality check excludes any other event's incident.
    """

    from app.models.sentinel_incident import SentinelIncident

    candidates = db.query(SentinelIncident).filter(
        SentinelIncident.containment_meta.like('%"source_event_id"%')
    ).order_by(SentinelIncident.id.asc()).all()
    for row in candidates:
        try:
            meta = json.loads(row.containment_meta or "")
        except Exception:
            continue
        if (
            isinstance(meta, dict)
            and meta.get("triggered_by") == "automation"
            and meta.get("source_event_id") == event_id
        ):
            return row
    return None


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def get_settings(db) -> AutomationSettings:
    settings = db.query(AutomationSettings).filter(
        AutomationSettings.id == 1
    ).first()
    if settings is None:
        settings = AutomationSettings(id=1)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def set_enabled(db, enabled: bool) -> AutomationSettings:
    settings = get_settings(db)
    settings.enabled = bool(enabled)
    db.commit()
    db.refresh(settings)
    return settings


# ---------------------------------------------------------------------------
# Queue
# ---------------------------------------------------------------------------

def enqueue_event(event_id: int, db=None) -> AutomationJob | None:
    """Create the pending job for one event, or return the existing one.

    One job per event is enforced by the unique index on event_id, so
    a second enqueue (double log, re-import, backfill overlap) can
    never queue the same event twice.
    """

    own_session = db is None
    if own_session:
        db = SessionLocal()
    try:
        existing = db.query(AutomationJob).filter(
            AutomationJob.event_id == event_id
        ).first()
        if existing is not None:
            return existing
        settings = get_settings(db)
        job = AutomationJob(
            event_id=event_id, status="pending",
            max_attempts=settings.max_attempts,
        )
        db.add(job)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return db.query(AutomationJob).filter(
                AutomationJob.event_id == event_id
            ).first()
        db.refresh(job)
        return job
    finally:
        if own_session:
            db.close()


def backfill_unqueued(db) -> dict:
    """Queue every security event that has no job yet (admin action)."""

    queued_ids = {
        row[0] for row in db.query(AutomationJob.event_id).filter(
            AutomationJob.event_id.isnot(None)
        ).all()
    }
    event_ids = [row[0] for row in db.query(SecurityEvent.id).order_by(
        SecurityEvent.id.asc()
    ).all()]
    created = 0
    failed = 0
    for event_id in event_ids:
        if event_id in queued_ids:
            continue
        try:
            enqueue_event(event_id, db=db)
            created += 1
        except Exception:
            logger.exception("automation backfill failed for event %s", event_id)
            failed += 1
    return {"created": created, "failed": failed, "already_queued": len(queued_ids)}


def reset_stale_processing(db) -> int:
    """Return crashed/interrupted jobs to pending (worker-start recovery).

    A job left in ``processing`` by a killed worker is not lost: its
    attempts are preserved and it is picked up again on the next pass.
    """

    count = db.query(AutomationJob).filter(
        AutomationJob.status == "processing"
    ).update(
        {"status": "pending", "next_attempt_at": None},
        synchronize_session=False,
    )
    if count:
        db.commit()
        logger.warning("automation: reset %d stale processing job(s)", count)
    return count


def retry_failed(db) -> int:
    """Manual retry: failed jobs go back to pending with a fresh budget."""

    count = db.query(AutomationJob).filter(
        AutomationJob.status == "failed"
    ).update(
        {"status": "pending", "attempts": 0, "next_attempt_at": None},
        synchronize_session=False,
    )
    if count:
        db.commit()
    return count


# ---------------------------------------------------------------------------
# Processing
# ---------------------------------------------------------------------------

def claim_next_job(db) -> AutomationJob | None:
    """Atomically claim the oldest due pending job for this worker."""

    now = _utcnow_naive()
    job = db.query(AutomationJob).filter(
        AutomationJob.status == "pending",
        (AutomationJob.next_attempt_at.is_(None))
        | (AutomationJob.next_attempt_at <= now),
    ).order_by(AutomationJob.created_at.asc()).first()
    if job is None:
        return None
    updated = db.query(AutomationJob).filter(
        AutomationJob.id == job.id,
        AutomationJob.status == "pending",
    ).update(
        {
            "status": "processing",
            "started_at": now,
            "attempts": AutomationJob.attempts + 1,
        },
        synchronize_session=False,
    )
    db.commit()
    if not updated:
        return None
    db.refresh(job)
    return job


def _fail_or_retry(db, job: AutomationJob, error: Exception) -> AutomationJob:
    job.error_message = str(error)[:MAX_ERROR_CHARS]
    if job.attempts >= job.max_attempts:
        job.status = "failed"
        job.completed_at = _utcnow_naive()
        logger.error(
            "automation: job %s for event %s failed permanently after %d attempts: %s",
            job.id, job.event_id, job.attempts, error,
        )
    else:
        settings = get_settings(db)
        delay = settings.backoff_base_seconds * (2 ** (job.attempts - 1))
        job.status = "pending"
        job.next_attempt_at = _utcnow_naive() + timedelta(seconds=delay)
        logger.warning(
            "automation: job %s for event %s failed (attempt %d/%d), retry in %ds: %s",
            job.id, job.event_id, job.attempts, job.max_attempts, delay, error,
        )
    db.commit()
    db.refresh(job)
    return job


def process_job(db, job: AutomationJob) -> AutomationJob:
    """Run one claimed job end to end. Raises RetryableError on failure."""

    start = time.perf_counter()
    event = db.query(SecurityEvent).filter(
        SecurityEvent.id == job.event_id
    ).first()
    if event is None:
        job.status = "failed"
        job.error_message = "event no longer exists"
        job.completed_at = _utcnow_naive()
        db.commit()
        db.refresh(job)
        return job

    log_text = _event_log_text(event)
    if not log_text.strip():
        job.verdict = None
        job.explanation = "No analyzable log text on this event; nothing was assessed."
        job.review_exclusion_reason = "empty_log_text"
        job.incident_outcome = "none"
        job.decision_source = "skipped"
        job.latency_ms = int((time.perf_counter() - start) * 1000)
        job.status = "completed"
        job.completed_at = _utcnow_naive()
        db.commit()
        db.refresh(job)
        return job

    classification = classify_log(log_text, kind="log")
    fused = fuse_classification(log_text, classification)
    if classification.get("status") == "unavailable":
        detail = classification.get("error") or "; ".join(
            classification.get("limitations") or ["model unavailable"]
        )
        raise RetryableError(f"CyberLLMv1 unavailable: {detail}")

    verdict = fused.get("fused_verdict")
    score = fused.get("fused_score")
    parse_ok = bool(classification.get("parse_ok"))

    # Bridge parity: a suspicious-by-construction event is never
    # suppressed as benign; floor it to needs_review like the bridge.
    if (
        _is_suspicious_event(event)
        and verdict == "likely_benign"
        and (score or 0) < BENIGN_SCORE_THRESHOLD
    ):
        fused = dict(fused)
        fused["fused_verdict"] = "needs_review"
        fused["fused_score"] = max(int(score or 0), BENIGN_SCORE_THRESHOLD)
        verdict = "needs_review"
        score = fused["fused_score"]

    # --- incident: link existing, link recent duplicate, or create ---
    incident = None
    outcome = "none"
    if event.incident_id:
        from app.models.sentinel_incident import SentinelIncident

        incident = db.query(SentinelIncident).filter(
            SentinelIncident.id == event.incident_id
        ).first()
        if incident is not None:
            outcome = "linked"
    if incident is None:
        # R2 crash-window recovery: if this pipeline already created
        # an incident for this event but the link was lost before the
        # job committed, reuse it instead of creating a second one —
        # regardless of how long ago the dedup window expired.
        orphan = _find_automation_incident_for_event(db, event.id)
        if orphan is not None:
            incident = orphan
            outcome = "linked"
            event.incident_id = orphan.id
    if incident is None:
        key = _dedup_key(event.ip_address, log_text)
        dup = _find_recent_duplicate(db, key)
        if dup is not None:
            incident = dup
            outcome = "linked"
            event.incident_id = dup.id
    incident_worthy = (
        verdict in ("likely_threat", "needs_review")
        or (score or 0) >= BENIGN_SCORE_THRESHOLD
        or _is_suspicious_event(event)
    )
    if incident is None and incident_worthy:
        meta = json.dumps({
            "dedup_key": _dedup_key(event.ip_address, log_text),
            "source_event_id": event.id,
            "triggered_by": "automation",
        })
        incident = create_incident(
            db, log_text=log_text, ip_address=event.ip_address,
            fused=fused, classification=classification,
            containment_meta=meta,
        )
        outcome = "created"
        event.incident_id = incident.id

    # --- AI Review candidacy (gated; human approval still mandatory) ---
    exclusion = None
    training_example_id = None
    if incident is not None and is_review_eligible(verdict, score) and parse_ok:
        try:
            example = collect_from_incident(db, incident)
        except Exception as exc:  # visible on the job, never silent (D3)
            logger.exception(
                "automation: training collection failed for incident %s", incident.id
            )
            example = None
        # R1: collect_from_incident never raises in practice — it
        # catches its own exceptions, rolls back and returns None. A
        # None result on this eligible path IS the failure, so record
        # it explicitly instead of leaving the job with no candidate
        # and no exclusion reason.
        if example is not None:
            training_example_id = example.id
        else:
            exclusion = "collection_failed"
    elif not parse_ok:
        exclusion = "model_output_unparseable"
    elif incident is None:
        exclusion = "benign_no_incident"
    else:
        exclusion = "benign_low_score"

    # R1: collect_from_incident commits on success but rolls the
    # session back on failure, and that rollback discards the pending
    # event.incident_id assignment made above. Re-assert the link here
    # so it survives to the final commit on either outcome; the job
    # row records the same id below, so job and event stay linked.
    if incident is not None and event.incident_id != incident.id:
        event.incident_id = incident.id

    summary = (classification.get("summary") or "").strip()
    reasoning = (classification.get("reasoning") or "").strip()
    explanation = " ".join(part for part in (summary, reasoning) if part)
    if not explanation:
        explanation = "; ".join(classification.get("limitations") or []) or (
            "No explanation provided by the assessment."
        )
    actions = classification.get("recommended_actions") or []
    recommended = actions[0] if actions else {
        "likely_threat": "Review the incident and confirm or reject it.",
        "needs_review": "Review this event.",
        "likely_benign": "No action required.",
    }.get(verdict, "Review this event.")
    rules_evidence = (fused.get("rules") or {}).get("evidence") or []
    evidence = (event.evidence or "") or "; ".join(str(e) for e in rules_evidence)
    assessment = {
        "verdict": verdict,
        "fused_score": score,
        "confidence": classification.get("confidence"),
        "decision_source": classification.get("status"),
        "components": fused.get("components"),
        "model_classification": classification.get("model_classification"),
        "inference_latency_ms": classification.get("latency_ms"),
        "output_tokens": classification.get("output_tokens"),
        "truncated": classification.get("truncated"),
    }

    job.verdict = verdict
    job.fused_score = score
    job.confidence = classification.get("confidence")
    job.severity = _SEVERITY_BY_VERDICT.get(verdict, "low")
    job.explanation = explanation[:MAX_EXPLANATION_CHARS]
    job.evidence = evidence[:MAX_EVIDENCE_CHARS]
    job.recommended_action = str(recommended)[:MAX_EXPLANATION_CHARS]
    job.mitre_technique = None  # classifier emits none; never invented
    job.decision_source = classification.get("status")
    job.assessment_json = json.dumps(assessment, ensure_ascii=False)[:MAX_ASSESSMENT_CHARS]
    job.review_exclusion_reason = exclusion
    job.incident_id = incident.id if incident is not None else None
    job.incident_outcome = outcome
    job.training_example_id = training_example_id
    job.error_message = None
    job.latency_ms = int((time.perf_counter() - start) * 1000)
    job.status = "completed"
    job.completed_at = _utcnow_naive()
    db.commit()
    db.refresh(job)
    return job


def process_one(db) -> AutomationJob | None:
    """Claim and process a single due job, handling retry/failure."""

    job = claim_next_job(db)
    if job is None:
        return None
    try:
        return process_job(db, job)
    except Exception as exc:
        return _fail_or_retry(db, job, exc)


# ---------------------------------------------------------------------------
# Worker thread
# ---------------------------------------------------------------------------

_worker_lock = threading.Lock()
_worker_thread: threading.Thread | None = None
_worker_stop: threading.Event | None = None


def _worker_loop(stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        try:
            db = SessionLocal()
            try:
                settings = get_settings(db)
                settings.worker_last_seen_at = _utcnow_naive()
                db.commit()
                poll = max(1, min(300, int(settings.poll_interval_seconds or 5)))
                process_one(db)
            finally:
                db.close()
        except Exception:
            logger.exception("automation worker iteration failed")
            poll = 5
        stop_event.wait(poll)


def start_worker() -> dict:
    """Start the worker thread (idempotent) and recover stale jobs."""

    global _worker_thread, _worker_stop
    with _worker_lock:
        if _worker_thread is not None and _worker_thread.is_alive():
            return {"running": True, "already": True}
        db = SessionLocal()
        try:
            reset_stale_processing(db)
        finally:
            db.close()
        _worker_stop = threading.Event()
        _worker_thread = threading.Thread(
            target=_worker_loop, args=(_worker_stop,),
            name="sentientai-automation-worker", daemon=True,
        )
        _worker_thread.start()
        return {"running": True, "already": False}


def stop_worker() -> dict:
    """Stop the worker thread. Pending jobs stay queued in the database."""

    global _worker_thread, _worker_stop
    with _worker_lock:
        thread, stop = _worker_thread, _worker_stop
        _worker_thread, _worker_stop = None, None
    if stop is not None:
        stop.set()
    if thread is not None:
        thread.join(timeout=10)
    return {"running": False}


def worker_state(db) -> dict:
    settings = get_settings(db)
    alive = _worker_thread is not None and _worker_thread.is_alive()
    last_seen = settings.worker_last_seen_at
    fresh = False
    if last_seen is not None:
        seen = last_seen.replace(tzinfo=None) if last_seen.tzinfo else last_seen
        window = max(30, 3 * int(settings.poll_interval_seconds or 5))
        fresh = (_utcnow_naive() - seen).total_seconds() <= window
    if alive and fresh:
        state = "running"
    elif alive:
        state = "stale"
    elif settings.enabled:
        state = "stopped"
    else:
        state = "paused"
    return {
        "state": state,
        "enabled": bool(settings.enabled),
        "thread_alive": alive,
        "last_seen_at": last_seen.isoformat() if last_seen else None,
        "poll_interval_seconds": settings.poll_interval_seconds,
        "max_attempts": settings.max_attempts,
    }


# ---------------------------------------------------------------------------
# Stats + history (dashboard data — always computed, never fabricated)
# ---------------------------------------------------------------------------

def get_stats(db) -> dict:
    from app.models.security_lab import SecurityLabRun
    from app.services.cyberllm_loader import get_status as loader_status

    total_events = db.query(func.count(SecurityEvent.id)).scalar() or 0

    def _count(*filters):
        return db.query(func.count(AutomationJob.id)).filter(*filters).scalar() or 0

    awaiting = _count(
        AutomationJob.status == "pending",
    )
    processing = _count(AutomationJob.status == "processing")
    completed = _count(AutomationJob.status == "completed")
    failed = _count(AutomationJob.status == "failed")
    scheduled_retry = _count(
        AutomationJob.status == "pending",
        AutomationJob.next_attempt_at.isnot(None),
    )
    benign = _count(
        AutomationJob.status == "completed",
        AutomationJob.verdict == "likely_benign",
    )
    suspicious = _count(
        AutomationJob.status == "completed",
        AutomationJob.verdict == "needs_review",
    )
    threats = _count(
        AutomationJob.status == "completed",
        AutomationJob.verdict == "likely_threat",
    )
    incidents_created = _count(AutomationJob.incident_outcome == "created")
    incidents_updated = _count(AutomationJob.incident_outcome == "linked")
    candidates = db.query(
        func.count(func.distinct(AutomationJob.training_example_id))
    ).filter(AutomationJob.training_example_id.isnot(None)).scalar() or 0
    avg_latency = db.query(func.avg(AutomationJob.latency_ms)).filter(
        AutomationJob.status == "completed",
        AutomationJob.latency_ms.isnot(None),
    ).scalar()
    unanalyzed_runs = db.query(func.count(SecurityLabRun.id)).filter(
        SecurityLabRun.analyzed_at.is_(None)
    ).scalar() or 0
    model_status = {"ready": False, "state": "unknown", "reason": "no status returned"}
    try:
        raw_status = loader_status()
    except Exception as exc:
        raw_status = None
        model_status = {"ready": False, "state": "unknown", "reason": str(exc)}
    if raw_status is not None:
        if isinstance(raw_status, dict):
            model_status = {
                "ready": bool(raw_status.get("ready")),
                "state": raw_status.get("state"),
                "reason": raw_status.get("reason"),
                "device": raw_status.get("device"),
            }
        else:
            # CyberLLMStatus dataclass (ready/state/reason/device/...).
            model_status = {
                "ready": bool(getattr(raw_status, "ready", False)),
                "state": getattr(raw_status, "state", None),
                "reason": getattr(raw_status, "reason", None),
                "device": getattr(raw_status, "device", None),
            }
    worker = worker_state(db)
    return {
        "automation_enabled": worker["enabled"],
        "worker": worker,
        "total_events": total_events,
        "awaiting_analysis": awaiting,
        "processing": processing,
        "completed": completed,
        "benign": benign,
        "suspicious": suspicious,
        "likely_threats": threats,
        "incidents_created": incidents_created,
        "incidents_updated": incidents_updated,
        "candidates_generated": candidates,
        "failed": failed,
        "retry_queue": failed + scheduled_retry,
        "scheduled_retries": scheduled_retry,
        "avg_latency_ms": round(float(avg_latency), 1) if avg_latency is not None else None,
        "unanalyzed_runs": unanalyzed_runs,
        "model": {
            "ready": bool(model_status.get("ready")),
            "state": model_status.get("state"),
            "reason": model_status.get("reason"),
            "device": model_status.get("device"),
        },
    }


def list_jobs(db, status: str | None = None, verdict: str | None = None,
              limit: int = 50) -> list[dict]:
    query = db.query(AutomationJob).order_by(AutomationJob.created_at.desc())
    if status:
        query = query.filter(AutomationJob.status == status)
    if verdict:
        query = query.filter(AutomationJob.verdict == verdict)
    jobs = query.limit(max(1, min(limit, 200))).all()
    event_ids = [j.event_id for j in jobs if j.event_id]
    events = {}
    if event_ids:
        for ev in db.query(SecurityEvent).filter(
            SecurityEvent.id.in_(event_ids)
        ).all():
            events[ev.id] = ev
    out = []
    for job in jobs:
        row = job.to_dict()
        ev = events.get(job.event_id)
        row["event"] = None
        if ev is not None:
            row["event"] = {
                "id": ev.id,
                "event_type": ev.event_type,
                "category": ev.category,
                "severity": ev.severity,
                "source": ev.source,
                "route": ev.route,
                "created_at": ev.created_at.isoformat() if ev.created_at else None,
            }
        out.append(row)
    return out


def get_job(db, job_id: int) -> dict | None:
    job = db.query(AutomationJob).filter(AutomationJob.id == job_id).first()
    if job is None:
        return None
    row = job.to_dict()
    ev = db.query(SecurityEvent).filter(
        SecurityEvent.id == job.event_id
    ).first() if job.event_id else None
    row["event"] = None
    if ev is not None:
        row["event"] = {
            "id": ev.id,
            "event_type": ev.event_type,
            "category": ev.category,
            "severity": ev.severity,
            "source": ev.source,
            "route": ev.route,
            "evidence": (ev.evidence or "")[:MAX_EVIDENCE_CHARS],
            "created_at": ev.created_at.isoformat() if ev.created_at else None,
        }
    return row
