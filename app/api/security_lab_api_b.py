"""Lab analyze + log-analyze endpoints (part B)."""
from __future__ import annotations
import json
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app.database import get_db
from app.services.auth_service import require_admin
from app.models.user import User
from app.api.security_lab_api_a import router, AnalyzeBody, LogAnalyzeBody

@router.post("/analyze")
def lab_analyze(body: AnalyzeBody, request: Request, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    log_text=None
    if body.log_text is not None:
        log_text=body.log_text.strip()
        if not log_text: raise HTTPException(status_code=422, detail="log_text empty")
    elif body.lab_run_id is not None:
        from app.models.security_lab import SecurityLabRun
        from app.models.attact_assessment import SecurityEvent
        run=db.query(SecurityLabRun).filter(SecurityLabRun.id==body.lab_run_id).first()
        if not run: raise HTTPException(status_code=404, detail="lab run not found")
        try: eids=json.loads(run.event_ids or "[]")
        except Exception: eids=[]
        rows=db.query(SecurityEvent).filter(SecurityEvent.id.in_(eids)).all() if eids else []
        parts=[]
        for e in rows: parts.append((e.evidence or e.event_type or "")[:1200])
        if not parts:
            try: meta=json.loads(run.meta_json or "{}")
            except Exception: meta={}
            synth=meta.get("synthetic_evidence")
            if synth: parts=[synth]
        if not parts: raise HTTPException(status_code=422, detail="no evidence for that lab run")
        log_text=" | ".join(parts)[:7000]
        try:
            mm=json.loads(run.meta_json or "{}")
            if mm.get("is_synthetic"): log_text="[SYNTHETIC EVIDENCE] "+log_text
        except Exception: pass
    elif body.event_ids:
        from app.models.attact_assessment import SecurityEvent
        rows=db.query(SecurityEvent).filter(SecurityEvent.id.in_(body.event_ids)).all()
        if not rows: raise HTTPException(status_code=404, detail="no events for ids")
        log_text=" | ".join((r.evidence or r.event_type or "")[:1200] for r in rows)[:7000]
    else:
        raise HTTPException(status_code=422, detail="provide lab_run_id or event_ids or log_text")
    from app.services.prompt_service import PROMPT_PATH, build_analysis_prompt
    from app.services.sentinel_inference import run_dual_inference
    from app.services.sentinel_schema import fuse_structured
    from app.services.incident_service import create_incident
    from app.services.sentinel_loader import get_status
    import time, re, ipaddress
    try: prompt_text=build_analysis_prompt(log_text)
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))
    ip_cands=re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", log_text); ip_addr=None
    for c in ip_cands:
        try: ipaddress.ip_address(c); ip_addr=c; break
        except Exception: pass
    status=get_status()
    t0=time.perf_counter()
    inference=run_dual_inference(prompt_text, max_new_tokens=body.max_new_tokens, timeout_s=18)
    fused=fuse_structured(log_text, inference)
    inc=None
    try: inc=create_incident(db, log_text=log_text, ip_address=ip_addr, fused={"fused_score": fused.get("fused_score", 50), "fused_verdict": fused.get("fused_verdict","needs_review"), "rules": fused.get("rules", {}) if isinstance(fused.get("rules"), dict) else {}}, inference=inference, prompt_path=str(PROMPT_PATH))
    except Exception: pass
    cand_id=None
    if inc is not None:
        try:
            from app.services.collection import collect_from_incident
            te=collect_from_incident(db, inc)
            cand_id=getattr(te,"id",None)
        except Exception: pass
    try: prompt_chars=len(prompt_text)
    except Exception: prompt_chars=None
    truncated=None
    try:
        from app.services.sentinel_loader import get_bundle
        tok=get_bundle().get("tokenizer")
        if tok and prompt_text:
            ids=tok.encode(prompt_text).ids
            budget=768 - body.max_new_tokens - 4
            truncated=len(ids) > budget
    except Exception: pass
    return {"log_text_preview": log_text[:800], "model_a": inference.get("model_a"), "model_b": inference.get("model_b"), "agreement": inference.get("agreement"), "agreement_detail": inference.get("agreement_detail"), "fusion": fused, "incident_id": getattr(inc,"id",None), "training_candidate_id": cand_id, "prompt_path": str(PROMPT_PATH), "prompt_chars": prompt_chars, "prompt_truncated": truncated, "ready": status.ready if hasattr(status,"ready") else None, "latency_ms": int((time.perf_counter()-t0)*1000)}

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
