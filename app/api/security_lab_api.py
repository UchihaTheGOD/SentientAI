"""Security Test Lab + Log Analyzer API (admin only)."""
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
    max_new_tokens: int = Field(default=96, ge=16, le=256)
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
def _lab_row_dict(r) -> dict:
    import json as _j
    from app.models.security_lab import SecurityLabRun as _RL
    try: m=_j.loads(r.meta_json or "{}")
    except Exception: m={}
    try: fusion=_j.loads(r.fusion_json) if getattr(r,"fusion_json",None) else None
    except Exception: fusion=None
    try: statuses=_j.loads(r.http_statuses or "[]")
    except Exception: statuses=[]
    try: cids=_j.loads(r.correlation_ids or "[]")
    except Exception: cids=[]
    try: eids=_j.loads(r.event_ids or "[]")
    except Exception: eids=[]
    # evidence summary for table view (first 240 chars of fusion or event evidence)
    return {"id": r.id, "created_at": r.created_at.isoformat() if r.created_at else None, "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "test_type": r.test_type, "target_url": r.target_url, "is_synthetic": bool(r.is_synthetic), "status": r.status, "detection_result": r.detection_result,
            "request_count": r.request_count, "response_count": r.response_count, "http_statuses": statuses, "correlation_ids": cids, "event_ids": eids,
            "error": r.error_message, "meta": m,
            "fused_verdict": getattr(r,"fused_verdict",None), "fused_score": getattr(r,"fused_score",None),
            "model_a_status": getattr(r,"model_a_status",None), "model_b_status": getattr(r,"model_b_status",None),
            "agreement": getattr(r,"agreement",None), "incident_id": getattr(r,"incident_id",None), "training_candidate_id": getattr(r,"training_candidate_id",None),
            "analyzed_at": r.analyzed_at.isoformat() if getattr(r,"analyzed_at",None) else None,
            "analysis_error": getattr(r,"analysis_error",None), "fusion": fusion}

def _report_links(db, run) -> dict:
    """Resolve status of linked incident/candidate for honest display."""
    from app.models.sentinel_incident import SentinelIncident
    from app.models.training_example import TrainingExample
    inc=None; ex=None
    try:
        if getattr(run,"incident_id",None): inc=db.query(SentinelIncident).filter(SentinelIncident.id==run.incident_id).first()
    except Exception: pass
    try:
        if getattr(run,"training_candidate_id",None): ex=db.query(TrainingExample).filter(TrainingExample.id==run.training_candidate_id).first()
    except Exception: pass
    return {"incident": {"id": inc.id, "status": inc.status, "fused_verdict": inc.fused_verdict} if inc else None,
            "training_example": {"id": ex.id, "status": ex.status, "safe_to_train": bool(ex.safe_to_train)} if ex else None}

@router.get("/runs")
def list_runs(limit: int = 20, test_type: str | None = None, status: str | None = None, severity: str | None = None, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    # Clamp at entry: a negative limit made min(limit, 50) negative,
    # and SQLAlchemy renders LIMIT -1 on SQLite as "no limit", so the
    # intended 50-row cap was defeated by a one-character input.
    limit = min(max(limit, 1), 50)
    from app.models.security_lab import SecurityLabRun
    q=db.query(SecurityLabRun).order_by(SecurityLabRun.created_at.desc())
    if test_type: q=q.filter(SecurityLabRun.test_type==test_type)
    if status: q=q.filter(SecurityLabRun.status==status)
    if severity:
        # severity lives in fusion_json; filter in Python for portability
        all_rows=q.limit(500).all()
        filtered=[]
        for _r in all_rows:
            try:
                fj=json.loads(_r.fusion_json or "{}") if getattr(_r,"fusion_json",None) else {}
                sev=(fj.get("rules",{}) or {}).get("severity") or _r.fused_verdict or ""
                if sev and sev.lower()==severity.lower(): filtered.append(_r)
                elif not sev and severity.lower()=="unavailable": filtered.append(_r)
            except Exception: 
                if severity.lower()=="unavailable": filtered.append(_r)
            if len(filtered)>=limit: break
        rows=filtered[:limit]
    else:
        rows=q.limit(limit).all()
    out=[]
    for r in rows:
        d=_lab_row_dict(r); d.update(_report_links(db,r)); out.append(d)
    return {"items": out, "count": len(out)}

@router.get("/runs/{rid}")
def get_run(rid: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from app.models.security_lab import SecurityLabRun
    from app.models.attact_assessment import SecurityEvent
    r = db.query(SecurityLabRun).filter(SecurityLabRun.id==rid).first()
    if not r: raise HTTPException(status_code=404, detail="not found")
    d=_lab_row_dict(r)
    try: eids=json.loads(r.event_ids or "[]")
    except Exception: eids=[]
    evs=[]
    if eids:
        rows = db.query(SecurityEvent).filter(SecurityEvent.id.in_(eids)).all()
        evs=[{"id": x.id, "event_type": x.event_type, "category": x.category, "severity": x.severity, "source": x.source, "evidence": (x.evidence or "")[:800], "correlation_id": x.correlation_id, "created_at": x.created_at.isoformat() if x.created_at else None} for x in rows]
    # Persisted Sentinel outputs (honest: may be empty/unavailable)
    links=_report_links(db,r)
    try: fusion=json.loads(r.fusion_json) if getattr(r,"fusion_json",None) else None
    except Exception: fusion=None
    return {**d, "event_ids": eids, "events": evs, "links": links, "fusion": fusion, "model_a_text": getattr(r,"model_a_text",None), "model_b_text": getattr(r,"model_b_text",None)}

def _persist_run_assessment(db: Session, run, inference: dict, fused: dict, incident, cand_id: int | None, *, analysis_error: str | None = None) -> None:
    # Legacy-named storage columns (see incident_service note): the
    # classifier slot holds the single CyberLLMv1 summary/status.
    try:
        run.model_a_text=(inference.get("summary") or "")[:4000] if inference.get("summary") else None
        run.model_a_status=inference.get("status")
        run.model_b_text=None
        run.model_b_status=None
        run.agreement=None
        run.fused_verdict=fused.get("fused_verdict")
        try: run.fused_score=int(fused.get("fused_score")) if fused.get("fused_score") is not None else None
        except Exception: run.fused_score=None
        try: run.fusion_json=json.dumps(fused, ensure_ascii=False)[:10000]
        except Exception: run.fusion_json=None
        if incident is not None: run.incident_id=getattr(incident,"id",None)
        if cand_id is not None: run.training_candidate_id=cand_id
        run.analysis_error=analysis_error
        from datetime import datetime as _dt, timezone as _tz
        run.analyzed_at=_dt.now(_tz.utc)
        db.commit(); db.refresh(run)
    except Exception:
        try: db.rollback()
        except Exception: pass

@router.post("/analyze")
def lab_analyze(body: AnalyzeBody, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    log_text=None
    input_truncated=False
    target_run=None
    if body.log_text is not None:
        log_text=body.log_text.strip()
        if not log_text: raise HTTPException(status_code=422, detail="log_text empty")
    elif body.lab_run_id is not None:
        from app.models.security_lab import SecurityLabRun
        from app.models.attact_assessment import SecurityEvent
        run=db.query(SecurityLabRun).filter(SecurityLabRun.id==body.lab_run_id).first()
        if not run: raise HTTPException(status_code=404, detail="lab run not found")
        target_run=run
        try: eids=json.loads(run.event_ids or "[]")
        except Exception: eids=[]
        rows=db.query(SecurityEvent).filter(SecurityEvent.id.in_(eids)).all() if eids else []
        raw_parts=[(e.evidence or e.event_type or "") for e in rows]
        parts=[p[:1200] for p in raw_parts]
        if not parts:
            try: meta=json.loads(run.meta_json or "{}")
            except Exception: meta={}
            synth=meta.get("synthetic_evidence")
            if synth: parts=[synth]
        if not parts: raise HTTPException(status_code=422, detail="no evidence for that lab run")
        joined=" | ".join(parts)
        # Disclose silent truncation: callers must know the model did
        # not see the full evidence (per-part 1200 cap, 7000 total).
        input_truncated=(any(len(p) > 1200 for p in raw_parts)
                         or len(joined) > 7000) if raw_parts else False
        log_text=joined[:7000]
        try:
            mm=json.loads(run.meta_json or "{}")
            if mm.get("is_synthetic"): log_text="[SYNTHETIC EVIDENCE] "+log_text
        except Exception: pass
    elif body.event_ids:
        from app.models.attact_assessment import SecurityEvent
        rows=db.query(SecurityEvent).filter(SecurityEvent.id.in_(body.event_ids)).all()
        if not rows: raise HTTPException(status_code=404, detail="no events for ids")
        raw_parts=[(r.evidence or r.event_type or "") for r in rows]
        joined=" | ".join(p[:1200] for p in raw_parts)
        input_truncated=(any(len(p) > 1200 for p in raw_parts)
                         or len(joined) > 7000)
        log_text=joined[:7000]
    else:
        raise HTTPException(status_code=422, detail="provide lab_run_id or event_ids or log_text")
    from app.services.classifier import classify_log, fuse_classification
    from app.services.incident_service import create_incident
    from app.services.cyberllm_loader import get_status
    import time, re, ipaddress
    ip_cands=re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", log_text); ip_addr=None
    for c in ip_cands:
        try: ipaddress.ip_address(c); ip_addr=c; break
        except Exception: pass
    status=get_status()
    t0=time.perf_counter()
    inference=classify_log(log_text, kind="log", max_new_tokens=body.max_new_tokens)
    fused=fuse_classification(log_text, inference)
    inc=None
    try: inc=create_incident(db, log_text=log_text, ip_address=ip_addr, fused={"fused_score": fused.get("fused_score", 50), "fused_verdict": fused.get("fused_verdict","needs_review"), "rules": fused.get("rules", {}) if isinstance(fused.get("rules"), dict) else {}}, classification=inference)
    except Exception: pass
    cand_id=None
    if inc is not None:
        try:
            from app.services.collection import collect_from_incident
            te=collect_from_incident(db, inc)
            cand_id=getattr(te,"id",None)
        except Exception: pass
    if target_run is not None:
        _persist_run_assessment(db, target_run, inference, fused, inc, cand_id)
    return {"log_text_preview": log_text[:800], "classification": inference, "fusion": fused, "incident_id": getattr(inc,"id",None), "training_candidate_id": cand_id, "ready": bool(status.ready) if hasattr(status,"ready") else None, "latency_ms": int((time.perf_counter()-t0)*1000), "lab_run_id": getattr(target_run,"id",None), "input_truncated": input_truncated, "input_chars": len(log_text)}

@router.post("/log-analyze")
def log_analyze(body: LogAnalyzeBody, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return lab_analyze(AnalyzeBody(log_text=body.log_text), request=None, db=db, user=user)

@router.delete("/runs/{rid}")
def delete_run(rid: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    from app.models.security_lab import SecurityLabRun
    r=db.query(SecurityLabRun).filter(SecurityLabRun.id==rid).first()
    if not r: raise HTTPException(status_code=404, detail="not found")
    db.delete(r); db.commit()
    return {"deleted": rid}

