"""AI Automation Center — dashboard page + API.

All endpoints are admin-only. POSTs go through the global CSRF
middleware like every other admin API. The page actions (forms) are
thin wrappers over the same service functions as the JSON API and
redirect back to the dashboard; the JSON API is for scripts and the
desktop scanner importer.

No endpoint here approves a training example, blocks an IP, or
executes remediation — those remain human actions elsewhere.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.attact_assessment import SecurityEvent
from app.models.user import User
from app.services import audit as audit_service
from app.services import automation as auto
from app.services.auth_service import require_admin
from app.services.security_events import log_event
from app.template_env import templates

router = APIRouter(tags=["automation"])

_API = "/api/security/automation"


def _audit(db, user, action: str, detail: str) -> None:
    try:
        audit_service.record(
            db, f"automation.{action}", user=user,
            target_type="automation", detail=detail,
        )
    except Exception:
        pass  # audit must never break the admin action itself


# ---------------------------------------------------------------------------
# Dashboard page
# ---------------------------------------------------------------------------

@router.get("/admin/automation", response_class=HTMLResponse)
def automation_page(request: Request, status: str | None = None,
                    db: Session = Depends(get_db),
                    user: User = Depends(require_admin)):
    stats = auto.get_stats(db)
    jobs = auto.list_jobs(db, status=status, limit=50)
    return templates.TemplateResponse("admin_automation.html", {
        "request": request, "current_user": user, "user": user,
        "stats": stats, "jobs": jobs, "filter_status": status or "",
    })


def _page_action(action: str):
    def _handler(request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_admin)):
        if action == "start":
            auto.set_enabled(db, True)
            result = auto.start_worker()
            _audit(db, user, "start", f"worker started (already={result.get('already')})")
        elif action == "pause":
            auto.set_enabled(db, False)
            auto.stop_worker()
            _audit(db, user, "pause", "worker stopped")
        elif action == "resume":
            auto.set_enabled(db, True)
            result = auto.start_worker()
            _audit(db, user, "resume", f"worker resumed (already={result.get('already')})")
        elif action == "retry-failed":
            count = auto.retry_failed(db)
            _audit(db, user, "retry_failed", f"{count} failed job(s) re-queued")
        elif action == "backfill":
            result = auto.backfill_unqueued(db)
            _audit(db, user, "backfill", f"queued {result['created']} event(s)")
        return RedirectResponse("/admin/automation", status_code=303)
    return _handler


for _name in ("start", "pause", "resume", "retry-failed", "backfill"):
    router.add_api_route(
        f"/admin/automation/{_name}", _page_action(_name),
        methods=["POST"], response_class=HTMLResponse,
    )


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------

@router.get(f"{_API}/stats")
def automation_stats(db: Session = Depends(get_db),
                     user: User = Depends(require_admin)):
    return auto.get_stats(db)


@router.get(f"{_API}/jobs")
def automation_jobs(status: str | None = None, verdict: str | None = None,
                    limit: int = 50, db: Session = Depends(get_db),
                    user: User = Depends(require_admin)):
    return {"items": auto.list_jobs(db, status=status, verdict=verdict, limit=limit)}


@router.get(f"{_API}/jobs/{{job_id}}")
def automation_job(job_id: int, db: Session = Depends(get_db),
                   user: User = Depends(require_admin)):
    row = auto.get_job(db, job_id)
    if row is None:
        raise HTTPException(status_code=404, detail="job not found")
    return row


@router.post(f"{_API}/start")
def automation_start(db: Session = Depends(get_db),
                     user: User = Depends(require_admin)):
    auto.set_enabled(db, True)
    result = auto.start_worker()
    _audit(db, user, "start", f"worker started (already={result.get('already')})")
    return {"enabled": True, "worker": result}


@router.post(f"{_API}/pause")
def automation_pause(db: Session = Depends(get_db),
                     user: User = Depends(require_admin)):
    auto.set_enabled(db, False)
    result = auto.stop_worker()
    _audit(db, user, "pause", "worker stopped")
    return {"enabled": False, "worker": result}


@router.post(f"{_API}/resume")
def automation_resume(db: Session = Depends(get_db),
                      user: User = Depends(require_admin)):
    auto.set_enabled(db, True)
    result = auto.start_worker()
    _audit(db, user, "resume", f"worker resumed (already={result.get('already')})")
    return {"enabled": True, "worker": result}


@router.post(f"{_API}/retry-failed")
def automation_retry_failed(db: Session = Depends(get_db),
                            user: User = Depends(require_admin)):
    count = auto.retry_failed(db)
    _audit(db, user, "retry_failed", f"{count} failed job(s) re-queued")
    return {"retried": count}


@router.post(f"{_API}/backfill")
def automation_backfill(db: Session = Depends(get_db),
                        user: User = Depends(require_admin)):
    result = auto.backfill_unqueued(db)
    _audit(db, user, "backfill", f"queued {result['created']} event(s)")
    return result


# ---------------------------------------------------------------------------
# Desktop scanner import (M1)
#
# Scanner findings are observations, NOT backend detections: they arrive
# here with source="desktop_scanner", keep their scan/finding identity
# in meta, and are analyzed by the same AI path as any other event —
# but they are never merged into middleware detections, and a scanner
# finding alone never becomes an incident without the normal
# eligibility + human-review gates. Re-importing the same scan_id is
# rejected so a scan cannot double-queue.
# ---------------------------------------------------------------------------

_SCANNER_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
_SCANNER_CONFIDENCES = {"high", "medium", "low"}
_SCANNER_STATUSES = {"suspected", "verified", "inconclusive"}
_SEVERITY_MAP = {
    "critical": "high", "high": "high", "medium": "medium",
    "low": "low", "informational": "low",
}
_CATEGORY_RE = re.compile(r"^[a-z0-9_]+$")


class ScannerFindingIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    category: str = Field(..., min_length=1, max_length=60)
    severity: str = Field(...)
    confidence: str = Field(...)
    status: str = Field(...)
    explanation: str = Field(default="", max_length=4000)
    evidence: str = Field(default="", max_length=8000)
    url: str | None = Field(default=None, max_length=1000)
    impact: str = Field(default="", max_length=2000)
    remediation: str = Field(default="", max_length=2000)


class ScannerImportIn(BaseModel):
    scan_id: str = Field(..., min_length=1, max_length=200)
    target: str = Field(..., min_length=1, max_length=1000)
    scanned_at: str | None = Field(default=None, max_length=100)
    findings: list[ScannerFindingIn] = Field(..., min_length=1, max_length=200)


@router.post(f"{_API}/scanner-import")
def automation_scanner_import(req: ScannerImportIn, request: Request,
                              db: Session = Depends(get_db),
                              user: User = Depends(require_admin)):
    parsed = urlparse(req.target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc \
            or parsed.username or parsed.password:
        raise HTTPException(
            status_code=422,
            detail="target must be an http(s) URL without embedded credentials",
        )
    # Duplicate scan: the same scan_id must not queue twice.
    escaped = req.scan_id.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    fragment = f'%"scan_id": "{escaped}"%'
    dup = db.query(SecurityEvent).filter(
        SecurityEvent.source == "desktop_scanner",
        SecurityEvent.meta_json.like(fragment, escape="\\"),
    ).first()
    if dup is not None:
        raise HTTPException(
            status_code=409, detail="scan already imported",
        )
    # Validate every finding BEFORE creating any event, so a bad
    # payload cannot leave a partial import behind.
    normalized: list[dict] = []
    for finding in req.findings:
        severity = finding.severity.lower()
        confidence = finding.confidence.lower()
        status = finding.status.lower()
        if severity not in _SCANNER_SEVERITIES:
            raise HTTPException(status_code=422, detail=f"invalid severity: {finding.severity}")
        if confidence not in _SCANNER_CONFIDENCES:
            raise HTTPException(status_code=422, detail=f"invalid confidence: {finding.confidence}")
        if status not in _SCANNER_STATUSES:
            raise HTTPException(status_code=422, detail=f"invalid status: {finding.status}")
        category = finding.category.lower().replace("-", "_")
        if not _CATEGORY_RE.match(category):
            raise HTTPException(status_code=422, detail=f"invalid category: {finding.category}")
        normalized.append({
            "finding": finding, "severity": severity,
            "confidence": confidence, "status": status, "category": category,
        })
    event_ids: list[int] = []
    job_ids: list[int] = []
    for item in normalized:
        finding = item["finding"]
        ev = log_event(
            db,
            event_type=f"scanner.{item['category']}",
            category=item["category"],
            severity=_SEVERITY_MAP[item["severity"]],
            confidence=item["confidence"],
            source="desktop_scanner",
            route=req.target[:300],
            evidence=(finding.evidence or finding.explanation or "")[:4000],
            meta={
                "scan_id": req.scan_id,
                "finding_name": finding.name,
                "target": req.target,
                "scanned_at": req.scanned_at,
                "scanner_severity": item["severity"],
                "scanner_confidence": item["confidence"],
                "scanner_status": item["status"],
                "scanner_verdict": item["status"],
                "explanation": finding.explanation[:2000],
                "impact": finding.impact[:2000],
                "remediation": finding.remediation[:2000],
                "url": finding.url,
            },
        )
        event_ids.append(ev.id)
        job = auto.enqueue_event(ev.id, db=db)
        if job is not None:
            job_ids.append(job.id)
    _audit(db, user, "scanner_import",
           f"scan {req.scan_id}: {len(event_ids)} finding(s) imported")
    return {
        "scan_id": req.scan_id, "target": req.target,
        "imported": len(event_ids), "event_ids": event_ids,
        "job_ids": job_ids,
    }
