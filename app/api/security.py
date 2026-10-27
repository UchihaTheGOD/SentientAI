"""Security admin API — ATTACT, events, triage + demo."""
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


class TriageBody(BaseModel):
    status: str
    note: str | None = None


@router.post("/findings/{fid}/triage")
def triage_finding(fid: int, body: TriageBody, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from datetime import datetime, timezone
    row = db.query(AttactFinding).filter(AttactFinding.id == fid).first()
    if not row:
        raise HTTPException(status_code=404, detail="not found")
    if body.status not in ("fixed", "false_positive", "open"):
        raise HTTPException(status_code=400, detail="invalid status")
    row.triage_status = body.status
    row.triage_note = (body.note or "")[:2000]
    row.triage_by = user.id
    row.triage_at = datetime.now(timezone.utc)
    db.commit()
    audit_svc.record(db, "moderation.action", user=user, target_type="attact_finding", target_id=str(fid), detail=f"triage {body.status}", request=request)
    return {"id": row.id, "triage_status": row.triage_status}


@router.post("/demo/run/{case_id}")
def demo_run(case_id: str, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from app.services.demo_cases import get_case
    from app.services.classifier import classify_log, fuse_classification
    from app.services.security_events import log_event, redact
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="unknown case")
    from app.main import create_app
    from starlette.testclient import TestClient
    app = create_app()
    c = TestClient(app)
    path = case["path"]
    method = case.get("method", "GET")
    c.get("/")
    csrf = c.cookies.get("csrf_token", "")
    if not path.startswith("/"):
        path = "/" + path
    try:
        if method == "GET":
            resp = c.get(path)
        elif method == "POST":
            payload = case.get("payload")
            if case_id == "csrf-01":
                resp = c.post(path, json={"log_text": "test"}, headers={})
            else:
                if payload:
                    resp = c.post(path, data=payload, headers={"X-CSRF-Token": csrf})
                else:
                    resp = c.post(path, headers={"X-CSRF-Token": csrf})
        elif method == "OPTIONS":
            resp = c.options(path)
        else:
            resp = c.get(path)
        resp_status = resp.status_code
        resp_text = resp.text[:3000] if hasattr(resp, "text") else ""
        resp_headers = dict(resp.headers) if hasattr(resp, "headers") else {}
    except Exception as e:
        resp_status = 500
        resp_text = str(e)[:2000]
        resp_headers = {}
    evidence = f"case {case_id} {method} {path} -> {resp_status} hdrs={list(resp_headers.keys())[:8]} body={resp_text[:600]}"
    evidence = redact(evidence) or evidence
    try:
        inference = classify_log(evidence, kind="log", max_new_tokens=64)
        fusion = fuse_classification(evidence, inference)
    except Exception as e:
        inference = {"source": "cyberllm", "status": "error", "error": str(e)[:300], "classification": "needs_review", "confidence": "low"}
        fusion = {"fused_verdict": "needs_review", "fused_score": 50, "error": str(e)[:500], "rules": {"evidence": []}}
    inc_id = None
    try:
        from datetime import datetime as _dt, timezone as _tz, timedelta as _td
        from app.services.incident_service import create_incident
        recent = db.query(SentinelIncident).filter(SentinelIncident.created_at >= _dt.now(_tz.utc) - _td(minutes=10)).all()
        dup = next((r for r in recent if r.log_text and evidence[:200] in (r.log_text or "")), None)
        if dup:
            inc_id = dup.id
        else:
            inc = create_incident(db, log_text=evidence, ip_address="127.0.0.1", fused={"fused_score": fusion.get("fused_score", 50), "fused_verdict": fusion.get("fused_verdict", "needs_review"), "rules": {"evidence": fusion.get("rules", {}).get("evidence", []) if isinstance(fusion.get("rules"), dict) else []}}, classification=inference)
            inc_id = inc.id
    except Exception:
        pass
    try:
        log_event(db, event_type="demo.run", category=case.get("category"), severity="info", confidence="high", source="demo", request=request, route=path, http_status=resp_status, evidence=evidence, meta={"case_id": case_id, "fusion": fusion.get("fused_verdict"), "incident_id": inc_id})
    except Exception:
        pass
    return {"case_id": case_id, "app_status": resp_status, "ground_truth": case.get("ground_truth", ""), "evidence": evidence, "fusion": fusion, "classification": inference, "incident_id": inc_id, "limitations": inference.get("limitations", [])}
