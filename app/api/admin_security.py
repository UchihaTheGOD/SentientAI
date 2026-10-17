"""Admin Security Center page."""
from __future__ import annotations
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.services.auth_service import require_admin
from app.models.user import User
from app.models.attact_assessment import AttactAssessment, SecurityEvent
from app.models.sentinel_incident import SentinelIncident, TempBlock
from app.services.demo_cases import catalog
from app.template_env import templates

router = APIRouter(prefix="/admin/security", tags=["admin-security"])

@router.get("", response_class=HTMLResponse)
def admin_security(request: Request, category: str | None = None, severity: str | None = None, ip: str | None = None, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    assessments = db.query(AttactAssessment).order_by(AttactAssessment.created_at.desc()).limit(20).all()
    incidents = db.query(SentinelIncident).order_by(SentinelIncident.created_at.desc()).limit(50).all()
    q = db.query(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(200)
    events = q.all()
    if category:
        events = [e for e in events if e.category == category]
    if severity:
        events = [e for e in events if e.severity == severity]
    if ip:
        events = [e for e in events if (e.ip_address or "") == ip]
    blocks = db.query(TempBlock).order_by(TempBlock.created_at.desc()).limit(20).all()
    return templates.TemplateResponse("admin_security.html", {"request": request, "current_user": user, "user": user, "assessments": assessments, "incidents": incidents, "events": events, "blocks": blocks, "demo_cases": catalog(), "filters": {"category": category, "severity": severity, "ip": ip}})

@router.get("/assessments/{aid}", response_class=HTMLResponse)
def assessment_detail(aid: int, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from app.models.attact_assessment import AttactFinding
    a = db.query(AttactAssessment).filter(AttactAssessment.id == aid).first()
    if not a:
        from fastapi import HTTPException
        raise HTTPException(status_code=404)
    findings = db.query(AttactFinding).filter(AttactFinding.assessment_id == aid).all()
    return templates.TemplateResponse("admin_security_detail.html", {"request": request, "current_user": user, "user": user, "assessment": a, "findings": findings})

# ---------------------------------------------------------------------------
# Controlled async submit for Sentinel analysis (admin-gated, not middleware)
# ---------------------------------------------------------------------------

from fastapi import BackgroundTasks, HTTPException
from pydantic import BaseModel

class AnalyzeEventBody(BaseModel):
    event_id: int

class AnalyzeFindingBody(BaseModel):
    finding_id: int

def _run_event_analysis_bg(event_id: int, triggered_by: int | None):
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        from app.services.sentinel_bridge import submit_security_event_for_analysis
        submit_security_event_for_analysis(db, event_id=event_id, triggered_by=triggered_by)
    except Exception as exc:
        import logging as _lg
        _lg.getLogger("sentientai.admin_security").exception("bg event analysis %s failed: %s", event_id, exc)
    finally:
        try: db.close()
        except Exception: pass

def _run_finding_analysis_bg(finding_id: int, triggered_by: int | None):
    from app.database import SessionLocal
    db = SessionLocal()
    try:
        from app.services.sentinel_bridge import submit_attact_finding_for_analysis
        submit_attact_finding_for_analysis(db, finding_id=finding_id, triggered_by=triggered_by)
    except Exception as exc:
        import logging as _lg
        _lg.getLogger("sentientai.admin_security").exception("bg finding analysis %s failed: %s", finding_id, exc)
    finally:
        try: db.close()
        except Exception: pass

@router.post("/analyze/event")
def analyze_event(body: AnalyzeEventBody, background_tasks: BackgroundTasks, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    ev = db.query(SecurityEvent).filter(SecurityEvent.id == body.event_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="event not found")
    # idempotency fast-path: already linked
    if ev.incident_id is not None:
        return {"status": "already_linked", "event_id": ev.id, "incident_id": ev.incident_id}
    # schedule background; logging of event already succeeded (deterministic)
    background_tasks.add_task(_run_event_analysis_bg, body.event_id, user.id)
    # also attempt synchronous short-circuit for tests (uses same DB session) if ?sync=1
    if request.query_params.get("sync") == "1":
        from app.services.sentinel_bridge import submit_security_event_for_analysis
        try:
            res = submit_security_event_for_analysis(db, event_id=body.event_id, triggered_by=user.id, request=request)
            inc = res.get("incident")
            return {"status": res.get("reason", "created"), "event_id": body.event_id, "incident_id": getattr(inc, "id", None), "is_duplicate": res.get("is_duplicate", False), "fused": res.get("fused")}
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)[:500])
    return {"status": "queued", "event_id": body.event_id}

@router.post("/analyze/finding")
def analyze_finding(body: AnalyzeFindingBody, background_tasks: BackgroundTasks, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from app.models.attact_assessment import AttactFinding
    f = db.query(AttactFinding).filter(AttactFinding.id == body.finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="finding not found")
    if f.incident_id is not None:
        return {"status": "already_linked", "finding_id": f.id, "incident_id": f.incident_id}
    background_tasks.add_task(_run_finding_analysis_bg, body.finding_id, user.id)
    if request.query_params.get("sync") == "1":
        from app.services.sentinel_bridge import submit_attact_finding_for_analysis
        try:
            res = submit_attact_finding_for_analysis(db, finding_id=body.finding_id, triggered_by=user.id, request=request)
            inc = res.get("incident")
            return {"status": res.get("reason", "created"), "finding_id": body.finding_id, "incident_id": getattr(inc, "id", None), "is_duplicate": res.get("is_duplicate", False), "fused": res.get("fused")}
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)[:500])
    return {"status": "queued", "finding_id": body.finding_id}

