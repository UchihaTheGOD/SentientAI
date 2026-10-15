"""Persisted ATTACT runner: wraps ATTACT/runner with DB + security_events, partial-failure safe."""
from __future__ import annotations
import json, time, logging
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from ATTACT.runner import run_assessment as _run, CHECKS
from ATTACT.scope import ScopeError
from app.models.attact_assessment import AttactAssessment, AttactFinding
from app.services.security_events import log_event, redact

logger = logging.getLogger("sentientai.attact")

_SEV_MAP = {"confirmed": "high", "potential": "medium", "not_found": "low", "not_run": "info"}


def run_and_persist(
    *,
    db: Session,
    target_url: str,
    allowlist: list[str] | None = None,
    confirm_authorized: bool = False,
    checks: list[str] | None = None,
    timeout: float = 6.0,
    max_requests: int = 120,
    created_by: int | None = None,
    request=None,
    correlation_id: str | None = None,
) -> tuple[AttactAssessment, object]:
    """Run ATTACT synchronously, persist assessment + findings + security_events.

    Never swallows ScopeError (caller maps to 403). On any other exception
    a partial assessment row is still persisted with status=error.
    """
    from app.models.attact_assessment import AttactAssessment as AA
    t0 = time.time()
    assessment = AA(
        run_id=__import__("uuid").uuid4().hex[:16],
        target=target_url,
        checks_requested=json.dumps(checks or CHECKS, ensure_ascii=False),
        checks_executed=json.dumps([], ensure_ascii=False),
        request_count=0,
        status="completed",
        allowlist=json.dumps(allowlist or [], ensure_ascii=False),
        created_by=created_by,
        created_at=datetime.now(timezone.utc),
    )
    # pre-persist so restart preserves at least the attempt
    try:
        db.add(assessment)
        db.commit()
        db.refresh(assessment)
    except Exception:
        db.rollback()

    try:
        report = _run(
            target_url=target_url,
            allowlist=allowlist,
            confirm_authorized=confirm_authorized,
            checks=checks,
            timeout=timeout,
            max_requests=max_requests,
        )
    except ScopeError:
        raise
    except Exception as exc:
        # persist as partial/error
        try:
            assessment.status = "error"
            assessment.error_message = str(exc)[:2000]
            assessment.finished_at = datetime.now(timezone.utc)
            assessment.elapsed_ms = int((time.time() - t0) * 1000)
            db.commit()
        except Exception:
            db.rollback()
        logger.exception("ATTACT run failed")
        raise
    # success path
    try:
        assessment.target = report.target
        assessment.timestamp = report.timestamp
        assessment.checks_executed = json.dumps(report.checks, ensure_ascii=False)
        assessment.request_count = report.request_count
        assessment.elapsed_ms = report.elapsed_ms
        assessment.allowlist = json.dumps(report.allowlist, ensure_ascii=False)
        assessment.limitations = json.dumps(report.limitations, ensure_ascii=False)
        assessment.report_json = json.dumps(report.to_dict(), ensure_ascii=False)[:100000]
        assessment.finished_at = datetime.now(timezone.utc)
        assessment.status = "completed"
        db.commit()
        db.refresh(assessment)
    except Exception:
        db.rollback()

    # findings + security events
    for f in report.findings:
        try:
            row = AttactFinding(
                assessment_id=assessment.id,
                check_name=f.check,
                title=f.title,
                status=f.status,
                severity=f.severity,
                confidence=f.confidence,
                summary=(f.summary or "")[:2000],
                evidence=redact(f.evidence or "") if f.evidence else None,
                remediation=(f.remediation or "")[:2000],
                request_count=getattr(f, "request_count", 0),
                meta_json=json.dumps(getattr(f, "meta", {}) or {}, ensure_ascii=False)[:8000],
            )
            db.add(row)
            db.flush()
            if f.status in ("confirmed", "potential"):
                log_event(
                    db,
                    event_type="attact.finding",
                    category=f.check,
                    severity=f.severity,
                    confidence=f.confidence,
                    source="attact",
                    request=request,
                    route=report.target,
                    assessment_id=assessment.id,
                    evidence=redact(f.evidence or f.summary or "")[:2000] if (f.evidence or f.summary) else None,
                    meta={"finding_id": row.id, "status": f.status, "check": f.check, "title": f.title},
                    correlation_id=correlation_id,
                )
            db.commit()
        except Exception:
            db.rollback()
            logger.exception("persist finding failed")

    return assessment, report
