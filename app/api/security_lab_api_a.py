"""Security Test Lab + Log Analyzer API (admin only) part A."""
from __future__ import annotations
import json
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.database import get_db
from app.services.auth_service import require_admin
from app.models.user import User
router = APIRouter(prefix="/api/security/lab", tags=["security-lab"])
class RunBody(BaseModel):
    test_type: str
    target_url: str | None = None
    custom_string: str | None = Field(default=None, max_length=300)
    count: int | None = Field(default=None, ge=1, le=6)
class AnalyzeBody(BaseModel):
    lab_run_id: int | None = None
    event_ids: list[int] | None = None
    log_text: str | None = Field(default=None, max_length=8000)
    max_new_tokens: int = Field(default=180, ge=16, le=256)
class LogAnalyzeBody(BaseModel):
    log_text: str = Field(..., min_length=1, max_length=8000)
@router.post("/run")
def lab_run(body: RunBody, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from app.services.security_lab_runner import run_lab_test
    custom = body.custom_string
    if body.count is not None and body.test_type == "login_fail": custom = f"count={body.count}"
    try: run = run_lab_test(db, test_type=body.test_type, target_url=body.target_url, custom_string=custom, created_by=user.id, request=request)
    except ValueError as e: raise HTTPException(status_code=400, detail=str(e))
    except Exception as e: raise HTTPException(status_code=500, detail=str(e)[:500])
    try: meta = json.loads(run.meta_json or "{}")
    except Exception: meta = {}
    return {"id": run.id, "test_type": run.test_type, "target_url": run.target_url, "is_synthetic": run.is_synthetic, "detection_result": run.detection_result, "request_count": run.request_count, "response_count": run.response_count, "http_statuses": json.loads(run.http_statuses or "[]"), "correlation_ids": json.loads(run.correlation_ids or "[]"), "event_ids": json.loads(run.event_ids or "[]"), "created_at": run.created_at.isoformat() if run.created_at else None, "completed_at": run.completed_at.isoformat() if run.completed_at else None, "meta": meta, "error": run.error_message}
@router.get("/runs")
def list_runs(limit: int = 20, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from app.models.security_lab import SecurityLabRun
    rows = db.query(SecurityLabRun).order_by(SecurityLabRun.created_at.desc()).limit(min(limit,50)).all()
    out=[]
    for r in rows:
        try: m=json.loads(r.meta_json or "{}")
        except Exception: m={}
        out.append({"id": r.id, "test_type": r.test_type, "target_url": r.target_url, "is_synthetic": r.is_synthetic, "detection_result": r.detection_result, "request_count": r.request_count, "response_count": r.response_count, "http_statuses": json.loads(r.http_statuses or "[]"), "event_ids": json.loads(r.event_ids or "[]"), "created_at": r.created_at.isoformat() if r.created_at else None, "error": r.error_message, "meta": m})
    return {"items": out}
@router.get("/runs/{rid}")
def get_run(rid: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from app.models.security_lab import SecurityLabRun
    from app.models.attact_assessment import SecurityEvent
    r = db.query(SecurityLabRun).filter(SecurityLabRun.id==rid).first()
    if not r: raise HTTPException(status_code=404, detail="not found")
    try: eids=json.loads(r.event_ids or "[]")
    except Exception: eids=[]
    evs=[]
    if eids:
        rows = db.query(SecurityEvent).filter(SecurityEvent.id.in_(eids)).all()
        evs=[{"id": x.id, "event_type": x.event_type, "category": x.category, "severity": x.severity, "source": x.source, "evidence": (x.evidence or "")[:800], "correlation_id": x.correlation_id, "created_at": x.created_at.isoformat() if x.created_at else None} for x in rows]
    try: m=json.loads(r.meta_json or "{}")
    except Exception: m={}
    return {"id": r.id, "test_type": r.test_type, "target_url": r.target_url, "is_synthetic": r.is_synthetic, "detection_result": r.detection_result, "request_count": r.request_count, "response_count": r.response_count, "http_statuses": json.loads(r.http_statuses or "[]"), "correlation_ids": json.loads(r.correlation_ids or "[]"), "event_ids": eids, "events": evs, "meta": m, "error": r.error_message, "created_at": r.created_at.isoformat() if r.created_at else None, "completed_at": r.completed_at.isoformat() if r.completed_at else None}
