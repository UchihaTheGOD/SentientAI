"""Admin panel routes.

Every route in this module depends on `require_admin`, so authorization is
enforced server-side on each endpoint rather than by hiding links — a normal
user who guesses a URL gets a 403, not a page. The panel is intentionally
small: overview, user management, content (posts/comments), reports, logs, the
assistant's review queue, and read-only settings.
"""
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response, RedirectResponse
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.audit import AUDIT_EVENT_TYPES
from app.models.blog_post import POST_PUBLISHED, POST_STATES, BlogPost
from app.models.learning import EXAMPLE_STATUS_LABELS
from app.models.moderation import REPORT_OPEN, REPORT_REVIEWING, Report
from app.models.social import Comment
from app.models.user import User
from app.models.learning import NEEDS_EDIT, REJECTION_REASONS
from app.models.training_example import TrainingExample
from app.services import audit
from app.services import admin_service
from app.services.auth_service import require_admin
from app.services.pagination import clamp_page, paginate
from app.services.sanitize import clean_text, strip_formatting
from app.services import training as training_service
from app.services.scoring import BAND_LABELS
from app.template_env import templates

router = APIRouter(prefix="/admin", tags=["admin"])

# Where a review action returns to. Restricted to a fixed allow-list so the
# `next` form field can never be turned into an open redirect.
_REVIEW_DESTINATIONS = {"/admin", "/admin/training"}


def _review_redirect(next_to: str) -> RedirectResponse:
    dest = next_to if next_to in _REVIEW_DESTINATIONS else "/admin"
    return RedirectResponse(url=dest, status_code=303)


@router.get("", response_class=HTMLResponse)
def admin_dashboard(
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    total_users = db.query(func.count(User.id)).scalar() or 0
    suspended_users = db.query(func.count(User.id)).filter(
        User.is_suspended == True).scalar() or 0  # noqa: E712
    total_posts = db.query(func.count(BlogPost.id)).scalar() or 0
    published_posts = db.query(func.count(BlogPost.id)).filter(
        BlogPost.status == POST_PUBLISHED).scalar() or 0
    total_comments = db.query(func.count(Comment.id)).scalar() or 0
    open_reports = db.query(func.count(Report.id)).filter(
        Report.status.in_((REPORT_OPEN, REPORT_REVIEWING))).scalar() or 0

    # Pending training examples awaiting review.
    pending = training_service.get_pending_examples(db)
    pending_count = len(pending)

    return templates.TemplateResponse("admin.html", {
        "request": request,
        "user": user,
        "current_user": user,
        "stats": {
            "total_users": total_users,
            "suspended_users": suspended_users,
            "total_posts": total_posts,
            "published_posts": published_posts,
            "total_comments": total_comments,
            "open_reports": open_reports,
            "pending_review": pending_count,
        },
        # Kept for backwards compatibility with anything reading these directly.
        "total_users": total_users,
        "pending_examples": pending,
        "pending_count": pending_count,
        "recent_events": audit.recent(db, limit=12),
    })


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

@router.get("/users", response_class=HTMLResponse)
def admin_users(
    request: Request,
    q: str = Query(""),
    role: str = Query(""),
    status: str = Query(""),
    page: int = Query(1),
    done: str = Query(""),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    term = clean_text(q, 100).strip()
    query = db.query(User)
    if term:
        like = f"%{term}%"
        query = query.filter(or_(User.username.ilike(like), User.email.ilike(like)))
    if role in ("user", "admin"):
        query = query.filter(User.role == role)
    if status == "suspended":
        query = query.filter(User.is_suspended == True)  # noqa: E712
    elif status == "active":
        query = query.filter(User.is_suspended == False)  # noqa: E712
    query = query.order_by(User.created_at.desc())
    users = paginate(query, clamp_page(page), 25)

    return templates.TemplateResponse("admin_users.html", {
        "request": request,
        "user": user,
        "current_user": user,
        "users": users,
        "q": term,
        "role": role,
        "status": status,
        "done": done,
        "params": {"q": term, "role": role, "status": status},
    })


# The confirmation phrase the operator must type to arm the bulk delete.
_REMOVE_ALL_PHRASE = "REMOVE ALL USERS"


# NOTE: the static /users/remove-all routes are declared *before* the dynamic
# /users/{user_id} route below. FastAPI matches in declaration order, and
# {user_id} would otherwise swallow "remove-all" (then 422 on the int cast).
@router.get("/users/remove-all", response_class=HTMLResponse)
def admin_remove_all_users_page(
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    normal_count = db.query(func.count(User.id)).filter(User.role != "admin").scalar() or 0
    return templates.TemplateResponse("admin_remove_all.html", {
        "request": request,
        "user": user,
        "current_user": user,
        "normal_count": normal_count,
    })


@router.post("/users/remove-all")
def admin_remove_all_users(
    request: Request,
    confirm: str = Form(""),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Delete every non-admin account and its data. Admins and system
    configuration are preserved. Guarded by an exact confirmation phrase so it
    can't be triggered by a stray click or a cross-site request."""
    if confirm.strip() != _REMOVE_ALL_PHRASE:
        raise HTTPException(
            status_code=400,
            detail=f'To confirm, type exactly: {_REMOVE_ALL_PHRASE}',
        )
    removed = admin_service.remove_all_normal_users(db)
    audit.record(db, "moderation.action", user=user, target_type="profile",
                 target_id="*", detail=f"remove_all_users: {removed} removed",
                 request=request)
    return RedirectResponse(
        url=f"/admin/users?done=removed-{removed}", status_code=303)


@router.get("/users/{user_id}", response_class=HTMLResponse)
def admin_user_detail(
    user_id: int,
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    target = db.query(User).filter(User.id == user_id).first()
    if target is None:
        raise HTTPException(status_code=404, detail="Account not found.")
    post_count = db.query(func.count(BlogPost.id)).filter(
        BlogPost.user_id == user_id).scalar() or 0
    comment_count = db.query(func.count(Comment.id)).filter(
        Comment.user_id == user_id).scalar() or 0
    report_count = db.query(func.count(Report.id)).filter(
        Report.reporter_id == user_id).scalar() or 0
    recent_posts = (
        db.query(BlogPost).filter(BlogPost.user_id == user_id)
        .order_by(BlogPost.created_at.desc()).limit(10).all()
    )
    account_events = [
        e for e in audit.recent(db, limit=200) if e.user_id == user_id
    ][:15]
    return templates.TemplateResponse("admin_user_detail.html", {
        "request": request,
        "user": user,
        "current_user": user,
        "account": target,
        "post_count": post_count,
        "comment_count": comment_count,
        "report_count": report_count,
        "recent_posts": recent_posts,
        "events": account_events,
    })


@router.post("/users/{user_id}/delete")
def admin_delete_user(
    user_id: int,
    request: Request,
    confirm: str = Form(""),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    target = db.query(User).filter(User.id == user_id).first()
    if target is None:
        raise HTTPException(status_code=404, detail="Account not found.")
    if target.id == user.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")
    if target.role == "admin":
        raise HTTPException(
            status_code=403,
            detail="Administrator accounts cannot be deleted from the admin panel.",
        )
    # A destructive, irreversible action: require the username typed back exactly.
    if confirm.strip() != target.username:
        raise HTTPException(status_code=400, detail="Confirmation did not match the username.")

    username = target.username
    admin_service.delete_user(db, target)
    audit.record(db, "moderation.action", user=user, target_type="profile",
                 target_id=str(user_id), detail=f"user_deleted: {username}",
                 request=request)
    return RedirectResponse(url="/admin/users?done=user-deleted", status_code=303)


# ---------------------------------------------------------------------------
# Posts
# ---------------------------------------------------------------------------

@router.get("/posts", response_class=HTMLResponse)
def admin_posts(
    request: Request,
    q: str = Query(""),
    state: str = Query(""),
    page: int = Query(1),
    done: str = Query(""),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    term = clean_text(q, 100).strip()
    query = db.query(BlogPost)
    if term:
        query = query.filter(BlogPost.title.ilike(f"%{term}%"))
    if state in POST_STATES:
        query = query.filter(BlogPost.status == state)
    elif state == "hidden":
        query = query.filter(BlogPost.is_hidden == True)  # noqa: E712
    query = query.order_by(BlogPost.created_at.desc())
    posts = paginate(query, clamp_page(page), 25)

    author_ids = {p.user_id for p in posts.items if p.user_id}
    authors = (
        {u.id: u for u in db.query(User).filter(User.id.in_(author_ids)).all()}
        if author_ids else {}
    )
    return templates.TemplateResponse("admin_posts.html", {
        "request": request,
        "user": user,
        "current_user": user,
        "posts": posts,
        "authors": authors,
        "q": term,
        "state": state,
        "done": done,
        "params": {"q": term, "state": state},
    })


@router.post("/posts/{post_id}/delete")
def admin_delete_post(
    post_id: int,
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    post = db.query(BlogPost).filter(BlogPost.id == post_id).first()
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found.")
    title = post.title
    admin_service.delete_post_cascade(db, post)
    db.commit()
    audit.record(db, "post.deleted", user=user, target_type="blog_post",
                 target_id=str(post_id), detail=f"admin removal: {title[:80]}",
                 request=request)
    return RedirectResponse(url="/admin/posts?done=post-deleted", status_code=303)


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------

@router.get("/comments", response_class=HTMLResponse)
def admin_comments(
    request: Request,
    page: int = Query(1),
    done: str = Query(""),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    query = db.query(Comment).order_by(Comment.created_at.desc())
    comments = paginate(query, clamp_page(page), 30)

    author_ids = {c.user_id for c in comments.items if c.user_id}
    authors = (
        {u.id: u for u in db.query(User).filter(User.id.in_(author_ids)).all()}
        if author_ids else {}
    )
    post_ids = {c.post_id for c in comments.items if c.post_id}
    posts = (
        {p.id: p for p in db.query(BlogPost).filter(BlogPost.id.in_(post_ids)).all()}
        if post_ids else {}
    )
    return templates.TemplateResponse("admin_comments.html", {
        "request": request,
        "user": user,
        "current_user": user,
        "comments": comments,
        "authors": authors,
        "posts": posts,
        "done": done,
    })


@router.post("/comments/{comment_id}/delete")
def admin_delete_comment(
    comment_id: int,
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    comment = db.query(Comment).filter(Comment.id == comment_id).first()
    if comment is None:
        raise HTTPException(status_code=404, detail="Comment not found.")
    from app.models.social import CommentLike
    db.query(CommentLike).filter(CommentLike.comment_id == comment_id).delete(
        synchronize_session=False)
    # Detach replies rather than delete them: one level of threading, and an
    # orphaned reply is still readable content.
    db.query(Comment).filter(Comment.parent_id == comment_id).update(
        {Comment.parent_id: None}, synchronize_session=False)
    db.delete(comment)
    db.commit()
    audit.record(db, "comment.deleted", user=user, target_type="comment",
                 target_id=str(comment_id), detail="admin removal", request=request)
    return RedirectResponse(url="/admin/comments?done=comment-deleted", status_code=303)


# ---------------------------------------------------------------------------
# Logs (read-only audit trail)
# ---------------------------------------------------------------------------

@router.get("/logs", response_class=HTMLResponse)
def admin_logs(
    request: Request,
    event_type: str = Query(""),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    selected = event_type if event_type in AUDIT_EVENT_TYPES else ""
    events = audit.recent(db, limit=200, event_type=selected or None)
    actor_ids = {e.user_id for e in events if e.user_id}
    actors = (
        {u.id: u for u in db.query(User).filter(User.id.in_(actor_ids)).all()}
        if actor_ids else {}
    )
    return templates.TemplateResponse("admin_logs.html", {
        "request": request,
        "user": user,
        "current_user": user,
        "events": events,
        "actors": actors,
        "event_types": AUDIT_EVENT_TYPES,
        "selected": selected,
    })


# ---------------------------------------------------------------------------
# Settings (read-only view of the runtime configuration)
# ---------------------------------------------------------------------------

@router.get("/settings", response_class=HTMLResponse)
def admin_settings(
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    # Only non-sensitive configuration is surfaced. Secrets (SECRET_KEY, SMTP
    # password) are shown as a configured/not-configured flag, never their value.
    config_rows = [
        ("Environment", settings.ENVIRONMENT),
        ("Database", _db_kind(settings.DATABASE_URL)),
        ("Access-token lifetime", f"{settings.ACCESS_TOKEN_EXPIRE_MINUTES} min"),
        ("Password-reset token lifetime", f"{settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES} min"),
        ("SECRET_KEY", "configured" if settings.SECRET_KEY else "MISSING"),
        ("SMTP host", settings.SMTP_HOST or "not configured (dev logs the link)"),
        ("SMTP port", str(settings.SMTP_PORT)),
        ("SMTP auth", "configured" if settings.SMTP_USERNAME else "none"),
        ("SMTP password", "configured" if settings.SMTP_PASSWORD else "not set"),
        ("SMTP from", settings.SMTP_FROM or "—"),
        ("SMTP STARTTLS", "on" if settings.SMTP_USE_TLS else "off"),
    ]
    return templates.TemplateResponse("admin_settings.html", {
        "request": request,
        "user": user,
        "current_user": user,
        "config_rows": config_rows,
    })


def _db_kind(url: str) -> str:
    """A safe label for the database, never the full URL (it may embed a
    password for non-SQLite backends)."""
    scheme = (url or "").split(":", 1)[0] or "unknown"
    return "SQLite" if scheme.startswith("sqlite") else scheme


@router.post("/training/{example_id}/approve")
def approve_training(
    example_id: int,
    request: Request,
    note: str = Form(""),
    label: str = Form(""),
    next: str = Form("/admin"),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    example = training_service.approve_example(
        db, example_id, user.id,
        note=clean_text(note, 500) or None,
        human_label=clean_text(label, 80) or None,
    )
    if example is None:
        raise HTTPException(status_code=404, detail="Training example not found.")
    audit.record(db, "training.candidate_approved", user=user,
                 target_type="training_example", target_id=str(example_id),
                 detail=f"status={example.status}", request=request)
    return _review_redirect(next)


@router.post("/training/{example_id}/reject")
def reject_training(
    example_id: int,
    request: Request,
    reason: str = Form("other"),
    note: str = Form(""),
    next: str = Form("/admin"),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    # Rejection keeps the row (see app/services/training.py) so the reason a
    # candidate was filtered out stays available for error analysis.
    example = training_service.reject_example(
        db, example_id, user.id, reason=reason, note=clean_text(note, 500) or None,
    )
    if example is None:
        raise HTTPException(status_code=404, detail="Training example not found.")
    audit.record(db, "training.candidate_rejected", user=user,
                 target_type="training_example", target_id=str(example_id),
                 detail=f"reason={reason}", request=request)
    return _review_redirect(next)


@router.get("/training", response_class=HTMLResponse)
def admin_training_queue(
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """The full review queue: every pending candidate with its triage score,
    band, and the reasons the scorer recorded — best-scoring first."""
    pending = training_service.get_pending_examples(db, limit=200)
    return templates.TemplateResponse("admin_training.html", {
        "request": request,
        "user": user,
        "current_user": user,
        "pending_examples": pending,
        "pending_count": len(pending),
        "band_labels": BAND_LABELS,
        "rejection_reasons": REJECTION_REASONS,
        "status_counts": training_service.status_counts(db),
    })


@router.get("/training/rejected", response_class=HTMLResponse)
def admin_training_rejected(
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Rejected and duplicate candidates, retained for error analysis."""
    rejected = training_service.get_rejected_examples(db, limit=200)
    return templates.TemplateResponse("admin_rejected.html", {
        "request": request,
        "user": user,
        "current_user": user,
        "rejected_examples": rejected,
    })


@router.post("/training/{example_id}/needs-edit")
def needs_edit_training(
    example_id: int,
    request: Request,
    note: str = Form(""),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Park a promising candidate that needs its text fixed before approval.

    It stays in the queue (still not trainable) rather than being approved or
    rejected outright."""
    example = training_service.review_example(
        db, example_id, user.id, NEEDS_EDIT,
        note=clean_text(note, 500) or None,
    )
    if example is None:
        raise HTTPException(status_code=404, detail="Training example not found.")
    audit.record(db, "training.candidate_needs_edit", user=user,
                 target_type="training_example", target_id=str(example_id),
                 detail=f"status={example.status}", request=request)
    return RedirectResponse(url="/admin/training", status_code=303)


@router.get("/export", response_class=Response)
def export_training_data(
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    jsonl = training_service.export_approved_jsonl(db)
    return Response(
        content=jsonl,
        media_type="application/jsonl",
        headers={"Content-Disposition": "attachment; filename=training_data.jsonl"},
    )
