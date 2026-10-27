"""Security analysis API — readiness, analysis, incidents & containment.

Classification is now provided by CyberLLMv1 (see app/services/classifier.py)
plus deterministic security rules. The obsolete Sentinel dual-model
inference, tokenizer, prompt file, and model-agreement logic were removed
in the 2026-10-27 migration; the route paths (/api/sentinel/*, /sentinel)
and the incident/review/block workflows are preserved, but the response
no longer contains model_a / model_b / agreement / prompt fields — those
were outputs of the retired models, not of the application.
"""
from __future__ import annotations
import time
import logging
from fastapi import APIRouter, Depends, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.database import get_db
from app.services.log_validation import validate_log_text, MAX_LOG_CHARS
from app.services.cyberllm_loader import get_status as cyberllm_status, ensure_loaded as cyberllm_ensure_loaded
from app.services.auth_service import get_current_user, require_admin
from app.models.user import User
from app.template_env import templates
logger = logging.getLogger("sentientai.sentinel.api")
router = APIRouter(tags=["sentinel"])

@router.get("/api/sentinel/readiness")
def readiness():
    """Classifier readiness: CyberLLMv1 status + deterministic rules availability.

    Rules are always available (model-independent). ``ready`` here means
    the CyberLLMv1 model is loaded; when it is not, analysis still works
    rules-only and honestly reports model_status=unavailable.
    """
    s = cyberllm_status()
    return {
        "ready": bool(s.ready),
        "classifier": "cyberllm",
        "base_model": s.base_model,
        "model_root": s.model_root,
        "adapter_dir": s.adapter_dir,
        "device": s.device,
        "reason": s.reason,
        "rss_mb": s.rss_mb,
        "rules_available": True,
        "legacy_models": "removed",
    }

@router.post("/api/sentinel/readiness/load")
def readiness_load(user: User = Depends(require_admin)):
    s = cyberllm_ensure_loaded()
    return {"ready": bool(s.ready), "classifier": "cyberllm", "reason": s.reason, "load_ms": s.load_ms}

class AnalyzeRequest(BaseModel):
    log_text: str = Field(..., min_length=1, max_length=MAX_LOG_CHARS)
    max_new_tokens: int | None = Field(default=None, ge=16, le=512)
    create_incident: bool = Field(default=True)

def _dedup_incident_key(db: Session, ip: str | None, log_text: str) -> str | None:
    """Hash of (ip, log head) for 10-min dedup window."""
    import hashlib
    key = hashlib.sha256(f"{ip or ''}:{(log_text or '')[:600]}".encode()).hexdigest()[:24]
    # look for recent incident with same key in last 10 min
    from datetime import datetime, timezone, timedelta
    from app.models.sentinel_incident import SentinelIncident
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=10)
    # dedup via containment_meta marker (lightweight, non-destructive)
    rows = db.query(SentinelIncident).filter(SentinelIncident.created_at >= cutoff).all()
    for r in rows:
        if r.containment_meta and key in (r.containment_meta or ""):
            return r.id  # signal duplicate
    return None

@router.post("/api/sentinel/analyze")
def analyze(req: AnalyzeRequest, request: Request, db: Session = Depends(get_db), user: User | None = Depends(get_current_user)):
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        log_text = validate_log_text(req.log_text)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    import re, ipaddress
    ip_cands = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", log_text)
    ip_addr = None
    for c in ip_cands:
        try:
            ipaddress.ip_address(c)
            ip_addr = c
            break
        except Exception:
            pass
    from app.services.classifier import classify_log, fuse_classification
    from app.services import incident_service
    start = time.perf_counter()
    classification = classify_log(log_text, kind="log", max_new_tokens=req.max_new_tokens)
    fused = fuse_classification(log_text, classification)
    latency_ms = int((time.perf_counter() - start)*1000)
    incident = None
    if req.create_incident:
        try:
            incident = incident_service.create_incident(db, log_text=log_text, ip_address=ip_addr, fused=fused, classification=classification)
        except Exception as exc:
            logger.exception("incident create failed: %s", exc)
    return {
        "classification": classification,
        "rules": fused.get("rules"),
        "fusion": {"score": fused.get("fused_score"), "verdict": fused.get("fused_verdict"), "components": fused.get("components"), "note": fused.get("note")},
        "risk_score": fused.get("fused_score"),
        "verdict": fused.get("fused_verdict"),
        "incident_id": getattr(incident, "id", None),
        "evidence": fused.get("rules", {}).get("evidence", []),
        "latency_ms": latency_ms,
        "inference_latency_ms": classification.get("latency_ms"),
    }

@router.get("/api/sentinel/incidents")
def list_incidents_api(status: str | None = None, limit: int = 20, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from app.services import incident_service
    rows = incident_service.list_incidents(db, status=status, limit=min(limit,100))
    return {"items": [{"id": r.id, "status": r.status, "fused_verdict": r.fused_verdict, "fused_score": r.fused_score, "ip_address": r.ip_address, "created_at": r.created_at.isoformat() if r.created_at else None} for r in rows]}

class ReviewRequest(BaseModel):
    status: str
    note: str | None = None

@router.post("/api/sentinel/incidents/{incident_id}/review")
def review_incident(incident_id: int, req: ReviewRequest, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from app.services import incident_service
    import app.services.audit as audit
    inc = incident_service.update_review(db, incident_id, user.id, req.status, note=req.note)
    if not inc:
        raise HTTPException(status_code=404, detail="incident not found")
    try:
        audit.record(db, "moderation.action", user=user, target_type="sentinel_incident", target_id=str(incident_id), detail=f"review:{req.status}", request=None)
    except Exception:
        pass
    return {"id": inc.id, "status": inc.status}

class BlockRequest(BaseModel):
    kind: str
    value: str
    ttl_minutes: int = 30
    reason: str | None = None
    incident_id: int | None = None

@router.post("/api/sentinel/blocks")
def create_block(req: BlockRequest, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from app.services import incident_service
    if req.kind not in ("ip","account","session"):
        raise HTTPException(status_code=422, detail="invalid kind")
    if req.kind == "account" and str(req.value) == str(user.id):
        raise HTTPException(status_code=400, detail="cannot block own account")
    if req.kind == "ip" and req.value in ("127.0.0.1","::1"):
        raise HTTPException(status_code=400, detail="allowlisted IP")
    try:
        blk = incident_service.apply_temp_block(db, kind=req.kind, value=req.value, ttl_minutes=req.ttl_minutes, reason=req.reason, created_by=user.id, incident_id=req.incident_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"id": blk.id, "kind": blk.kind, "value": blk.value, "expires_at": blk.expires_at.isoformat() if blk.expires_at else None, "active": blk.active}

@router.post("/api/sentinel/blocks/{block_id}/revoke")
def revoke_block(block_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from app.services import incident_service
    blk = incident_service.revoke_block(db, block_id, revoked_by=user.id)
    if not blk:
        raise HTTPException(status_code=404, detail="block not found")
    return {"id": blk.id, "active": blk.active}



@router.get("/api/sentinel/blocks")
def list_blocks(active: bool | None = None, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from app.models.sentinel_incident import TempBlock
    q = db.query(TempBlock).order_by(TempBlock.created_at.desc()).limit(50)
    rows = q.all()
    if active is not None:
        rows = [r for r in rows if r.active == active]
    return {"items": [{"id": r.id, "kind": r.kind, "value": r.value, "active": r.active, "expires_at": r.expires_at.isoformat() if r.expires_at else None} for r in rows]}

@router.get("/api/sentinel/training/candidates")
def list_candidates(user: User = Depends(require_admin)):
    from app.services.training_pipeline import list_candidates as lc, active_candidate
    return {"candidates": [str(p) for p in lc()], "active": str(active_candidate()) if active_candidate() else None}

@router.post("/api/sentinel/training/build")
def build_candidate(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from app.models.sentinel_incident import SentinelIncident
    from app.services.training_pipeline import build_dataset, evaluate_candidate, save_candidate
    reviewed = db.query(SentinelIncident).filter(SentinelIncident.status.in_(("confirmed_threat","false_positive"))).all()
    train, eval_set = build_dataset(reviewed)
    metrics = evaluate_candidate(train, eval_set)
    if metrics.get("status") == "insufficient_data":
        return {"status": "insufficient_data", "metrics": metrics, "train": len(train), "eval": len(eval_set)}
    path = save_candidate(train, eval_set, metrics)
    return {"status": "candidate_saved", "path": str(path), "metrics": metrics}

@router.post("/api/sentinel/training/approve")
def approve_candidate(path: str = Form(...), db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from pathlib import Path
    from app.services.training_pipeline import approve_candidate as ac
    p = Path(path)
    if not p.exists():
        raise HTTPException(status_code=404, detail="candidate not found")
    ac(p, user.id)
    return {"approved": str(p)}

@router.post("/api/sentinel/training/rollback")
def rollback_candidate(user: User = Depends(require_admin)):
    from app.services.training_pipeline import rollback
    ok = rollback()
    return {"rolled_back": ok}

@router.get("/sentinel", response_class=HTMLResponse)
def sentinel_page(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user is None:
        return RedirectResponse(url="/login?next=/sentinel", status_code=303)
    s = cyberllm_status()
    from app.services import incident_service
    recent = incident_service.list_incidents(db, limit=10)
    return templates.TemplateResponse("sentinel.html", {"request": request, "current_user": user, "user": user, "status": s, "prompt_preview": "", "recent_incidents": recent})

@router.get("/admin/sentinel/incidents", response_class=HTMLResponse)
def admin_sentinel_incidents(request: Request, status: str | None = None, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from app.services import incident_service
    rows = incident_service.list_incidents(db, status=status, limit=100)
    from app.models.sentinel_incident import TempBlock
    blocks = db.query(TempBlock).order_by(TempBlock.created_at.desc()).limit(20).all()
    return templates.TemplateResponse("admin_sentinel.html", {"request": request, "current_user": user, "user": user, "incidents": rows, "blocks": blocks, "filter_status": status})
