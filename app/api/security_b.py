"""Security admin API part B: triage + demo (imported by security_a)."""
from __future__ import annotations
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.database import get_db
from app.services.auth_service import require_admin
from app.models.user import User
from app.models.attact_assessment import AttactFinding
from app.models.sentinel_incident import SentinelIncident
from app.services import audit as audit_svc
from app.api.security_a import router

class TriageBody(BaseModel):
    status: str
    note: str | None = None

@router.post("/findings/{fid}/triage")
def triage_finding(fid: int, body: TriageBody, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from datetime import datetime, timezone
    row = db.query(AttactFinding).filter(AttactFinding.id == fid).first()
    if not row:
        raise HTTPException(status_code=404, detail="not found")
    if body.status not in ("fixed","false_positive","open"):
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
    from app.services.sentinel_loader import ensure_loaded
    from app.services.prompt_service import build_analysis_prompt
    from app.services.sentinel_inference import run_dual_inference
    from app.services.sentinel_schema import fuse_structured
    from app.services.security_events import log_event, redact
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="unknown case")
    from app.main import create_app
    from starlette.testclient import TestClient
    app = create_app()
    c = TestClient(app)
    path = case["path"]
    method = case.get("method","GET")
    c.get("/")
    csrf = c.cookies.get("csrf_token","")
    if not path.startswith("/"):
        path = "/" + path
    try:
        if method == "GET":
            resp = c.get(path)
        elif method == "POST":
            payload = case.get("payload")
            if case_id == "csrf-01":
                resp = c.post(path, json={"log_text":"test"}, headers={})
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
    ensure_loaded()
    try:
        prompt = build_analysis_prompt(evidence, extra_prompt=f"Demo {case_id} {case.get('category')}")
        inference = run_dual_inference(prompt, max_new_tokens=64, timeout_s=12)
        fusion = fuse_structured(evidence, inference)
    except Exception as e:
        inference = {"model_a": {"status":"error","error":str(e)[:300]}, "model_b": {"status":"error","error":str(e)[:300]}}
        fusion = {"fused_verdict":"needs_review","fused_score":50,"error":str(e)[:500]}
    inc_id = None
    try:
        from datetime import datetime as _dt, timezone as _tz, timedelta as _td
        from app.services.incident_service import create_incident
        recent = db.query(SentinelIncident).filter(SentinelIncident.created_at >= _dt.now(_tz.utc)-_td(minutes=10)).all()
        dup = next((r for r in recent if r.log_text and evidence[:200] in (r.log_text or "")), None)
        if dup:
            inc_id = dup.id
        else:
            inc = create_incident(db, log_text=evidence, ip_address="127.0.0.1", fused={"fused_score": fusion.get("fused_score",50), "fused_verdict": fusion.get("fused_verdict","needs_review"), "rules": {"evidence": fusion.get("rules",{}).get("evidence",[]) if isinstance(fusion.get("rules"), dict) else []}}, inference=inference)
            inc_id = inc.id
    except Exception:
        pass
    try:
        log_event(db, event_type="demo.run", category=case.get("category"), severity="info", confidence="high", source="demo", request=request, route=path, http_status=resp_status, evidence=evidence, meta={"case_id": case_id, "fusion": fusion.get("fused_verdict"), "incident_id": inc_id})
    except Exception:
        pass
    return {"case_id": case_id, "app_status": resp_status, "ground_truth": case.get("ground_truth",""), "evidence": evidence, "fusion": fusion, "inference": inference, "incident_id": inc_id, "limitations": fusion.get("legacy_fusion",{}).get("limitations",[]) if isinstance(fusion.get("legacy_fusion"), dict) else []}
