"""Security admin API part A: ATTACT."""
from __future__ import annotations
import json
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.database import get_db
from app.services.auth_service import require_admin
from app.models.user import User
from app.models.attact_assessment import AttactAssessment, AttactFinding, SecurityEvent
from app.models.sentinel_incident import SentinelIncident
from app.services import audit as audit_svc

router = APIRouter(prefix="/api/security", tags=["security"])

class AttactRunBody(BaseModel):
    target: str = "http://127.0.0.1:8000"
    checks: list[str] | None = None
    timeout: float = 6.0
    max_requests: int = 120
    allowlist: list[str] | None = None

@router.post("/attact/run")
def attact_run(body: AttactRunBody, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from ATTACT.scope import ScopeError
    from app.services.attact_runner import run_and_persist
    cid = getattr(request.state, "correlation_id", None)
    try:
        assessment, report = run_and_persist(
            db=db, target_url=body.target, allowlist=body.allowlist,
            confirm_authorized=True, checks=body.checks, timeout=body.timeout,
            max_requests=body.max_requests, created_by=user.id, request=request, correlation_id=cid,
        )
    except ScopeError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)[:500])
    audit_svc.record(db, "moderation.action", user=user, target_type="attact_assessment", target_id=str(assessment.id), detail=f"attact run {assessment.run_id}", request=request)
    return {"assessment_id": assessment.id, "run_id": assessment.run_id, "target": assessment.target, "request_count": assessment.request_count, "findings": len(report.findings), "status": assessment.status}

@router.get("/assessments")
def list_assessments(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    rows = db.query(AttactAssessment).order_by(AttactAssessment.created_at.desc()).limit(50).all()
    return {"items": [{"id": r.id, "run_id": r.run_id, "target": r.target, "created_at": r.created_at.isoformat() if r.created_at else None, "request_count": r.request_count, "status": r.status} for r in rows]}

@router.get("/assessments/{aid}/export")
def export_assessment(aid: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    row = db.query(AttactAssessment).filter(AttactAssessment.id == aid).first()
    if not row:
        raise HTTPException(status_code=404, detail="not found")
    data = json.loads(row.report_json) if row.report_json else {}
    return JSONResponse(data)

@router.get("/events")
def list_events(category: str | None = None, severity: str | None = None, source: str | None = None, ip: str | None = None, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    q = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(200)
    rows = q.all()
    if category:
        rows = [r for r in rows if r.category == category]
    if severity:
        rows = [r for r in rows if r.severity == severity]
    if source:
        rows = [r for r in rows if r.source == source]
    if ip:
        rows = [r for r in rows if (r.ip_address or "") == ip]
    return {"items": [{"id": r.id, "created_at": r.created_at.isoformat() if r.created_at else None, "event_type": r.event_type, "category": r.category, "severity": r.severity, "source": r.source, "evidence": r.evidence} for r in rows]}

@router.get("/events/export")
def export_events(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    rows = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(500).all()
    return {"items": [{"id": r.id, "event_type": r.event_type, "evidence": r.evidence} for r in rows]}
