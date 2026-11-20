"""Admin user-management JSON API (CyberLLMv1 Security Lab).

Every route depends on ``require_admin``: authorization is enforced
server-side, so hiding a GUI button is never the control. The GUI
communicates only through these endpoints (plus the existing public
password-reset flow); it never touches the database directly.

Safety rules, all enforced here:
- Only safe account fields are ever returned: never password hashes,
  token versions, or session material.
- An administrator cannot change their own role, deactivate, or
  suspend themselves (lockout prevention).
- Demoting, deactivating, or suspending an admin requires at least
  two active admins to remain (last-admin guard).
- Role/activation/suspension changes bump ``token_version`` so the
  affected sessions die immediately, matching the model's stated
  invalidation policy.
- Every mutation is audit-recorded without secrets.
- No delete endpoint: deactivation is the reversible control, and
  deletion stays in the website admin panel under its existing
  username-confirmation guard.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.api.auth import _validate_registration
from app.database import get_db
from app.models.audit import AuditEvent
from app.models.blog_post import BlogPost
from app.models.moderation import Report
from app.models.social import Comment
from app.models.user import User
from app.services import audit
from app.services import password_reset as reset_service
from app.services.auth_service import hash_password, require_admin

router = APIRouter(prefix="/api/admin", tags=["admin-users"])

VALID_ROLES = ("user", "admin")


def user_to_dict(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "is_active": bool(user.is_active),
        "is_suspended": bool(user.is_suspended),
        "suspension_reason": user.suspension_reason,
        "display_name": user.display_name,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "can_sign_in": bool(user.can_sign_in),
    }


def _active_admin_count(db: Session) -> int:
    return db.query(func.count(User.id)).filter(
        User.role == "admin",
        User.is_active == True,  # noqa: E712
        User.is_suspended == False,  # noqa: E712
    ).scalar() or 0


def _get_target(db: Session, user_id: int) -> User:
    target = db.query(User).filter(User.id == user_id).first()
    if target is None:
        raise HTTPException(status_code=404, detail="Account not found.")
    return target


def _refuse_self(actor: User, target: User, action: str) -> None:
    if target.id == actor.id:
        raise HTTPException(
            status_code=400,
            detail=f"Administrators cannot {action} their own account.")


def _refuse_last_admin(db: Session, target: User, action: str) -> None:
    """Refuse a change that would leave zero active admins."""
    if target.role == "admin" and target.is_active and not target.is_suspended:
        if _active_admin_count(db) <= 1:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot {action}: at least one active administrator "
                       "must remain.")


def _bump_sessions(target: User) -> None:
    target.token_version = (target.token_version or 0) + 1


@router.get("/users")
def list_users(
    q: str = Query(""),
    role: str = Query(""),
    status: str = Query(""),
    sort: str = Query("recent"),
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    query = db.query(User)
    term = (q or "").strip()
    if term:
        like = f"%{term}%"
        query = query.filter(or_(User.username.ilike(like),
                                 User.email.ilike(like)))
    if role in VALID_ROLES:
        query = query.filter(User.role == role)
    if status == "suspended":
        query = query.filter(User.is_suspended == True)  # noqa: E712
    elif status == "inactive":
        query = query.filter(User.is_active == False)  # noqa: E712
    elif status == "active":
        query = query.filter(User.is_active == True,  # noqa: E712
                             User.is_suspended == False)  # noqa: E712
    total = query.count()
    if sort == "username":
        query = query.order_by(User.username.asc())
    elif sort == "role":
        query = query.order_by(User.role.asc(), User.created_at.desc())
    else:
        query = query.order_by(User.created_at.desc())
    users = query.offset((page - 1) * per_page).limit(per_page).all()
    recent = db.query(User).order_by(User.created_at.desc()).limit(5).all()
    return {
        "total": total,
        "admins": db.query(func.count(User.id)).filter(
            User.role == "admin").scalar() or 0,
        "active": db.query(func.count(User.id)).filter(
            User.is_active == True,  # noqa: E712
            User.is_suspended == False).scalar() or 0,  # noqa: E712
        "suspended": db.query(func.count(User.id)).filter(
            User.is_suspended == True).scalar() or 0,  # noqa: E712
        "page": page,
        "per_page": per_page,
        "users": [user_to_dict(u) for u in users],
        "recent": [user_to_dict(u) for u in recent],
    }


# NOTE: declared before /users/{user_id}: FastAPI matches in declaration
# order, and {user_id} would otherwise swallow "audit-events" (422 on int).
@router.get("/audit-events")
def list_audit_events(
    limit: int = Query(50, ge=1, le=100),
    event_type: str = Query(""),
    user_id: int | None = Query(None),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    events = audit.recent(db, limit=200,
                          event_type=event_type or None)
    if user_id is not None:
        events = [e for e in events if e.user_id == user_id]
    return {"events": [{
        "id": e.id, "event_type": e.event_type, "user_id": e.user_id,
        "actor_label": e.actor_label, "target_type": e.target_type,
        "target_id": e.target_id, "detail": e.detail,
        "created_at": e.created_at.isoformat() if e.created_at else None,
    } for e in events[:limit]]}


@router.get("/users/{user_id}")
def get_user(
    user_id: int,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    target = _get_target(db, user_id)
    events = [e for e in audit.recent(db, limit=200)
              if e.user_id == user_id][:15]
    return {
        "user": user_to_dict(target),
        "post_count": db.query(func.count(BlogPost.id)).filter(
            BlogPost.user_id == user_id).scalar() or 0,
        "comment_count": db.query(func.count(Comment.id)).filter(
            Comment.user_id == user_id).scalar() or 0,
        "report_count": db.query(func.count(Report.id)).filter(
            Report.reporter_id == user_id).scalar() or 0,
        "events": [{
            "id": e.id, "event_type": e.event_type, "user_id": e.user_id,
            "actor_label": e.actor_label, "target_type": e.target_type,
            "target_id": e.target_id, "detail": e.detail,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        } for e in events],
    }


class RoleChange(BaseModel):
    role: str = Field(...)


@router.patch("/users/{user_id}/role")
def set_role(
    user_id: int,
    body: RoleChange,
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    if body.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role.")
    target = _get_target(db, user_id)
    _refuse_self(user, target, "change the role of")
    if target.role == "admin" and body.role != "admin":
        _refuse_last_admin(db, target, "demote the last active administrator")
    old_role = target.role
    target.role = body.role
    _bump_sessions(target)
    db.commit()
    audit.record(db, "admin.user_role_changed", user=user,
                 target_type="profile", target_id=str(user_id),
                 detail=f"role: {old_role} -> {body.role}", request=request)
    return user_to_dict(target)


class ActiveChange(BaseModel):
    is_active: bool = Field(...)


@router.patch("/users/{user_id}/active")
def set_active(
    user_id: int,
    body: ActiveChange,
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    target = _get_target(db, user_id)
    _refuse_self(user, target, "deactivate" if not body.is_active else "activate")
    if not body.is_active:
        _refuse_last_admin(db, target, "deactivate the last active administrator")
    target.is_active = body.is_active
    _bump_sessions(target)
    db.commit()
    event = "admin.user_activated" if body.is_active else "admin.user_deactivated"
    audit.record(db, event, user=user, target_type="profile",
                 target_id=str(user_id),
                 detail=f"is_active set to {body.is_active}", request=request)
    return user_to_dict(target)


class SuspendChange(BaseModel):
    is_suspended: bool = Field(...)
    reason: str | None = Field(default=None, max_length=255)


@router.patch("/users/{user_id}/suspend")
def set_suspended(
    user_id: int,
    body: SuspendChange,
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    target = _get_target(db, user_id)
    _refuse_self(user, target, "suspend" if body.is_suspended else "unsuspend")
    if body.is_suspended:
        _refuse_last_admin(db, target, "suspend the last active administrator")
    target.is_suspended = body.is_suspended
    target.suspension_reason = body.reason if body.is_suspended else None
    target.suspended_at = (datetime.now(timezone.utc) if body.is_suspended
                           else None)
    _bump_sessions(target)
    db.commit()
    event = ("admin.user_suspended" if body.is_suspended
             else "admin.user_unsuspended")
    audit.record(db, event, user=user, target_type="profile",
                 target_id=str(user_id),
                 detail=f"is_suspended set to {body.is_suspended}",
                 request=request)
    return user_to_dict(target)


class CreateUser(BaseModel):
    username: str = Field(...)
    email: str = Field(...)
    password: str = Field(...)
    role: str = Field(default="user")


@router.post("/users", status_code=201)
def create_user(
    body: CreateUser,
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    error = _validate_registration(body.username, body.email,
                                   body.password, body.password)
    if error:
        raise HTTPException(status_code=400, detail=error)
    if body.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role.")
    username = body.username.strip()
    email = body.email.strip().lower()
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=409, detail="Username already taken.")
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=409, detail="Email already registered.")
    target = User(username=username, email=email,
                  password_hash=hash_password(body.password), role=body.role)
    db.add(target)
    db.commit()
    db.refresh(target)
    audit.record(db, "admin.user_created", user=user, target_type="profile",
                 target_id=str(target.id),
                 detail=f"created {username} role={body.role}", request=request)
    return user_to_dict(target)


@router.post("/users/{user_id}/password-reset")
def initiate_password_reset(
    user_id: int,
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    target = _get_target(db, user_id)
    base = str(request.base_url).rstrip("/")

    def build_url(raw: str) -> str:
        return f"{base}/reset-password?token={raw}"

    # The existing flow is enumeration-safe and generic by design; the
    # admin call inherits that behaviour (and its SMTP dependency).
    reset_service.initiate_reset(db, email=target.email, build_url=build_url)
    audit.record(db, "admin.password_reset_initiated", user=user,
                 target_type="profile", target_id=str(user_id),
                 detail=f"reset initiated for {target.username}",
                 request=request)
    return {"detail": "Password reset initiated. If email delivery is "
                       "configured, the user will receive a reset link."}
