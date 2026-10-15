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
