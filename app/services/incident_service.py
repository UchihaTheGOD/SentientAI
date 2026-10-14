"""Incident CRUD + reversible containment (Phase 5)."""
from __future__ import annotations
import json
from datetime import datetime, timezone, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from app.models.sentinel_incident import SentinelIncident, TempBlock, INCIDENT_STATUSES
from app.services.prompt_service import prompt_snapshot as get_prompt_snapshot, PROMPT_PATH

def _safe_snapshot() -> str:
    try:
        return get_prompt_snapshot()[:5000]
    except (FileNotFoundError, ValueError, OSError, RuntimeError) as _exc:
        return f"[prompt unavailable: {_exc}]"[:5000]
def create_incident(db: Session, *, log_text: str, ip_address: str | None, fused: dict, inference: dict, prompt_path: str | None = None) -> SentinelIncident:
    excerpt = (log_text or "")[:2000]
    evidence_json = json.dumps(fused.get("rules", {}).get("evidence", [])[:20])
    ma = (inference.get("model_a") or {}); mb = (inference.get("model_b") or {})
    inc = SentinelIncident(
        log_text=log_text, log_excerpt=excerpt, ip_address=ip_address,
        fused_score=fused.get("fused_score"), fused_verdict=fused.get("fused_verdict"),
        model_a_text=ma.get("text","")[:4000] if ma.get("text") else None,
        model_b_text=mb.get("text","")[:4000] if mb.get("text") else None,
        model_a_status=ma.get("status"), model_b_status=mb.get("status"),
        agreement=inference.get("agreement"), evidence=evidence_json,
        prompt_snapshot=_safe_snapshot(), prompt_path=str(prompt_path or PROMPT_PATH),
        status="pending_review", severity=fused.get("fused_verdict") or "pending_review",
    )
    db.add(inc); db.commit(); db.refresh(inc)
    return inc
def update_review(db: Session, incident_id: int, reviewer_id: int, new_status: str, note: str | None = None) -> Optional[SentinelIncident]:
    if new_status not in INCIDENT_STATUSES:
        raise ValueError(f"Unknown status {new_status}")
    inc = db.query(SentinelIncident).filter(SentinelIncident.id == incident_id).first()
    if not inc:
        return None
    inc.status = new_status
    inc.severity = new_status
    inc.reviewer_id = reviewer_id
    inc.reviewed_at = datetime.now(timezone.utc)
    inc.review_note = note
    inc.updated_at = inc.reviewed_at
    db.commit(); db.refresh(inc)
    return inc
def list_incidents(db: Session, status: str | None = None, limit: int = 100) -> list[SentinelIncident]:
    q = db.query(SentinelIncident).order_by(SentinelIncident.created_at.desc())
    if status:
        q = q.filter(SentinelIncident.status == status)
    return q.limit(limit).all()
ALLOWLIST_IPS = {"127.0.0.1","::1"}
DEFAULT_TTL_MIN = 30
def apply_temp_block(db: Session, *, kind: str, value: str, ttl_minutes: int = 30, reason: str | None = None, created_by: int | None = None, incident_id: int | None = None) -> TempBlock:
    if kind not in ("ip","account","session"):
        raise ValueError("unknown block kind")
    if kind == "ip" and _is_allowlisted(value):
        raise ValueError("allowlisted IP cannot be blocked")
    ttl = max(1, min(int(ttl_minutes or 30), 1440))
    existing = db.query(TempBlock).filter(TempBlock.kind==kind, TempBlock.value==str(value), TempBlock.active==True).first()  # noqa: E712
    if existing and existing.expires_at and existing.expires_at > datetime.now(timezone.utc):
        existing.expires_at = datetime.now(timezone.utc) + timedelta(minutes=ttl)
        existing.reason = reason or existing.reason
        db.commit(); db.refresh(existing)
        return existing
    blk = TempBlock(kind=kind, value=str(value), reason=reason, created_by=created_by, expires_at=datetime.now(timezone.utc)+timedelta(minutes=ttl), active=True, incident_id=incident_id)
    db.add(blk); db.commit(); db.refresh(blk)
    if kind == "account":
        try:
            from app.models.user import User
            u = db.query(User).filter(User.id==int(value)).first()
            if u and u.role != "admin":
                u.is_suspended = True
                u.suspension_reason = reason or "temporary containment"
                u.suspended_at = datetime.now(timezone.utc)
                u.token_version = (u.token_version or 0) + 1
                db.commit()
        except Exception:
            db.rollback()
    elif kind == "session":
        try:
            from app.models.user import User
            u = db.query(User).filter(User.id==int(value)).first()
            if u:
                u.token_version = (u.token_version or 0) + 1
                db.commit()
        except Exception:
            db.rollback()
    return blk

def revoke_block(db: Session, block_id: int, revoked_by: int | None = None) -> Optional[TempBlock]:
    blk = db.query(TempBlock).filter(TempBlock.id==block_id).first()
    if not blk:
        return None
    blk.active = False
    blk.revoked_at = datetime.now(timezone.utc)
    blk.revoked_by = revoked_by
    if blk.kind == "account":
        try:
            from app.models.user import User
            other = db.query(TempBlock).filter(TempBlock.kind=="account", TempBlock.value==blk.value, TempBlock.active==True).first()  # noqa: E712
            if not other:
                u = db.query(User).filter(User.id==int(blk.value)).first()
                if u:
                    u.is_suspended = False
                    u.suspension_reason = None
        except Exception:
            pass
    db.commit(); db.refresh(blk)
    return blk

def _aware(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def is_blocked(db: Session, kind: str, value: str) -> bool:
    now = datetime.now(timezone.utc)
    try:
        # Use aware comparison; expire stale
        rows = db.query(TempBlock).filter(TempBlock.active==True).all()  # noqa: E712
        expired = [r for r in rows if _aware(r.expires_at) and _aware(r.expires_at) <= now]
        for e in expired:
            e.active = False
        if expired:
            db.commit()
    except Exception:
        db.rollback()
    blk = db.query(TempBlock).filter(TempBlock.kind==kind, TempBlock.value==str(value), TempBlock.active==True).first()  # noqa: E712
    if not blk:
        return False
    exp = _aware(blk.expires_at)
    if exp and exp <= datetime.now(timezone.utc):
        blk.active = False; db.commit()
        return False
    return True

def cleanup_expired(db: Session) -> int:
    now = datetime.now(timezone.utc)
    rows = db.query(TempBlock).filter(TempBlock.active==True).all()  # noqa: E712
    expired = [r for r in rows if _aware(r.expires_at) and _aware(r.expires_at) <= now]
    for r in expired:
        r.active = False
    if expired:
        db.commit()
    return len(expired)

MAX_TTL_MIN = 1440
def _is_allowlisted(ip: str | None) -> bool:
    if not ip:
        return False
    return ip.strip() in ALLOWLIST_IPS
