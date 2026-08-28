"""Reporting and moderation.

Two tiers, enforced by dependencies rather than by hiding buttons:

  * any signed-in user may *report* content (`/report`) — nothing else;
  * only `require_admin` accounts may see the queue or act on content.

Every administrative decision writes a `ModerationAction` row and an
`AuditEvent`, so the queue is auditable after the fact. Hiding is reversible —
we set `is_hidden` rather than deleting, so a mistaken call can be undone and
the original content is still there for review.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.blog_post import BlogPost
from app.models.moderation import (
    MODERATION_ACTIONS, REPORT_DISMISSED, REPORT_OPEN, REPORT_REASON_LABELS,
    REPORT_REASONS, REPORT_RESOLVED, REPORT_REVIEWING, REPORT_STATUSES,
    REPORT_TARGETS, ModerationAction, Report,
)
from app.models.social import Comment
from app.models.user import User
from app.services import audit
from app.services.auth_service import get_current_user, require_admin
from app.services.pagination import clamp_page, paginate
from app.services.ratelimit import limit_report
from app.services.sanitize import clean_text, strip_formatting
from app.template_env import templates

router = APIRouter(tags=["moderation"])

MAX_DETAILS = 1000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _target_label(db: Session, target_type: str, target_id: int) -> str | None:
    """A short snapshot of what was reported, so the queue stays readable even
    if the content is later edited or removed."""
    if target_type == "post":
        post = db.query(BlogPost).filter(BlogPost.id == target_id).first()
        return post.title[:300] if post else None
    if target_type == "comment":
        comment = db.query(Comment).filter(Comment.id == target_id).first()
        return strip_formatting(comment.body, 200) if comment else None
    if target_type == "profile":
        user = db.query(User).filter(User.id == target_id).first()
        return f"@{user.username}" if user else None
    return None


def _target_exists(db: Session, target_type: str, target_id: int) -> bool:
    model = {"post": BlogPost, "comment": Comment, "profile": User}.get(target_type)
    if model is None:
        return False
    return db.query(model.id).filter(model.id == target_id).first() is not None


def _target_url(target_type: str, target_id: int, db: Session) -> str:
    if target_type == "post":
        post = db.query(BlogPost).filter(BlogPost.id == target_id).first()
        return f"/blog/{post.slug}" if post else "/blog"
    if target_type == "comment":
        comment = db.query(Comment).filter(Comment.id == target_id).first()
        if comment:
            post = db.query(BlogPost).filter(BlogPost.id == comment.post_id).first()
            if post:
                return f"/blog/{post.slug}#comment-{comment.id}"
        return "/blog"
    if target_type == "profile":
        user = db.query(User).filter(User.id == target_id).first()
        return f"/u/{user.username}" if user else "/community"
    return "/"


def log_action(
    db: Session,
    moderator: User,
    action: str,
    target_type: str,
    target_id: int,
    *,
    reason: str | None = None,
    report_id: int | None = None,
    request: Request | None = None,
) -> None:
    """Record one moderation decision. Never silently skips an unknown action."""
    if action not in MODERATION_ACTIONS:
        raise ValueError(f"Unknown moderation action: {action}")
    db.add(ModerationAction(
        moderator_id=moderator.id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        report_id=report_id,
        reason=reason[:255] if reason else None,
    ))
    db.commit()
    audit.record(
        db, "moderation.action", user=moderator,
        target_type=target_type, target_id=target_id,
        detail=f"{action}: {reason or 'no reason given'}",
        request=request,
    )


def _admin_redirect(status_filter: str, message: str) -> RedirectResponse:
    suffix = f"&status={status_filter}" if status_filter else ""
    return RedirectResponse(url=f"/admin/moderation?done={message}{suffix}",
                            status_code=303)


# ---------------------------------------------------------------------------
# Reporting — any signed-in user
# ---------------------------------------------------------------------------

@router.get("/report", response_class=HTMLResponse)
def report_form(
    request: Request,
    type: str = Query("post"),
    id: int = Query(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if type not in REPORT_TARGETS or not _target_exists(db, type, id):
        raise HTTPException(status_code=404, detail="Nothing to report there.")
    return templates.TemplateResponse("report.html", {
        "request": request,
        "current_user": user,
        "target_type": type,
        "target_id": id,
        "target_label": _target_label(db, type, id),
        "target_url": _target_url(type, id, db),
        "reasons": REPORT_REASONS,
        "reason_labels": REPORT_REASON_LABELS,
        "error": None,
        "submitted": False,
    })


@router.post("/report", response_class=HTMLResponse,
             dependencies=[Depends(limit_report)])
def report_submit(
    request: Request,
    target_type: str = Form(...),
    target_id: int = Form(...),
    reason: str = Form(...),
    details: str = Form(""),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    def render(error: str | None, submitted: bool = False, status_code: int = 200):
        return templates.TemplateResponse("report.html", {
            "request": request,
            "current_user": user,
            "target_type": target_type,
            "target_id": target_id,
            "target_label": _target_label(db, target_type, target_id),
            "target_url": _target_url(target_type, target_id, db),
            "reasons": REPORT_REASONS,
            "reason_labels": REPORT_REASON_LABELS,
            "error": error,
            "submitted": submitted,
        }, status_code=status_code)

    if target_type not in REPORT_TARGETS:
        raise HTTPException(status_code=400, detail="Unknown report target.")
    if not _target_exists(db, target_type, target_id):
        raise HTTPException(status_code=404, detail="Nothing to report there.")
    if reason not in REPORT_REASONS:
        return render("Please choose a reason from the list.", status_code=400)

    # One open report per user per target: repeat submissions are pointless and
    # would let one account flood the queue.
    existing = (
        db.query(Report)
        .filter(
            Report.reporter_id == user.id,
            Report.target_type == target_type,
            Report.target_id == target_id,
            Report.status.in_((REPORT_OPEN, REPORT_REVIEWING)),
        )
        .first()
    )
    if existing:
        return render(None, submitted=True)

    db.add(Report(
        reporter_id=user.id,
        target_type=target_type,
        target_id=target_id,
        target_label=_target_label(db, target_type, target_id),
        reason=reason,
        details=clean_text(details, MAX_DETAILS) or None,
        status=REPORT_OPEN,
    ))
    db.commit()
    audit.record(db, "report.created", user=user, target_type=target_type,
                 target_id=target_id, detail=f"reason={reason}", request=request)
    audit.bump_metric(db, "reports")
    return render(None, submitted=True)


# ---------------------------------------------------------------------------
# Queue — admins only
# ---------------------------------------------------------------------------

@router.get("/admin/moderation", response_class=HTMLResponse)
def moderation_queue(
    request: Request,
    status: str = Query(""),
    page: int = Query(1),
    done: str = Query(""),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    status_filter = status if status in REPORT_STATUSES else ""
    query = db.query(Report)
    if status_filter:
        query = query.filter(Report.status == status_filter)
    else:
        query = query.filter(Report.status.in_((REPORT_OPEN, REPORT_REVIEWING)))
    query = query.order_by(Report.created_at.desc())
    reports = paginate(query, clamp_page(page), 20)

    reporters = {}
    ids = {r.reporter_id for r in reports.items if r.reporter_id}
    if ids:
        reporters = {u.id: u for u in db.query(User).filter(User.id.in_(ids)).all()}

    counts = {}
    for state in REPORT_STATUSES:
        counts[state] = db.query(Report.id).filter(Report.status == state).count()

    recent_actions = (
        db.query(ModerationAction)
        .order_by(ModerationAction.created_at.desc())
        .limit(15)
        .all()
    )
    moderator_ids = {a.moderator_id for a in recent_actions if a.moderator_id}
    moderators = (
        {u.id: u for u in db.query(User).filter(User.id.in_(moderator_ids)).all()}
        if moderator_ids else {}
    )

    return templates.TemplateResponse("admin/moderation.html", {
        "request": request,
        "current_user": admin,
        "user": admin,
        "reports": reports,
        "reporters": reporters,
        "target_urls": {
            r.id: _target_url(r.target_type, r.target_id, db) for r in reports.items
        },
        "counts": counts,
        "statuses": REPORT_STATUSES,
        "status_filter": status_filter,
        "recent_actions": recent_actions,
        "moderators": moderators,
        "done": done,
        "params": {"status": status_filter},
    })


@router.post("/admin/moderation/{report_id}/resolve")
def resolve_report(
    report_id: int,
    request: Request,
    note: str = Form(""),
    status_filter: str = Form(""),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    report = db.query(Report).filter(Report.id == report_id).first()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    report.status = REPORT_RESOLVED
    report.resolved_by = admin.id
    report.resolved_at = datetime.now(timezone.utc)
    report.resolution_note = clean_text(note, 500) or None
    db.commit()
    log_action(db, admin, "report_resolved", report.target_type, report.target_id,
               reason=report.resolution_note, report_id=report.id, request=request)
    return _admin_redirect(status_filter, "resolved")


@router.post("/admin/moderation/{report_id}/dismiss")
def dismiss_report(
    report_id: int,
    request: Request,
    note: str = Form(""),
    status_filter: str = Form(""),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    report = db.query(Report).filter(Report.id == report_id).first()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    report.status = REPORT_DISMISSED
    report.resolved_by = admin.id
    report.resolved_at = datetime.now(timezone.utc)
    report.resolution_note = clean_text(note, 500) or None
    db.commit()
    log_action(db, admin, "report_dismissed", report.target_type, report.target_id,
               reason=report.resolution_note, report_id=report.id, request=request)
    return _admin_redirect(status_filter, "dismissed")


# ---------------------------------------------------------------------------
# Acting on content — admins only. Reversible by design.
# ---------------------------------------------------------------------------

@router.post("/admin/moderation/post/{post_id}/hide")
def hide_post(
    post_id: int,
    request: Request,
    reason: str = Form(""),
    report_id: int = Form(0),
    status_filter: str = Form(""),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    post = db.query(BlogPost).filter(BlogPost.id == post_id).first()
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found.")
    post.is_hidden = True
    post.hidden_reason = clean_text(reason, 255) or "Hidden by a moderator."
    db.commit()
    log_action(db, admin, "post_hidden", "post", post_id,
               reason=post.hidden_reason, report_id=report_id or None, request=request)
    return _admin_redirect(status_filter, "post-hidden")


@router.post("/admin/moderation/post/{post_id}/restore")
def restore_post(
    post_id: int,
    request: Request,
    status_filter: str = Form(""),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    post = db.query(BlogPost).filter(BlogPost.id == post_id).first()
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found.")
    post.is_hidden = False
    post.hidden_reason = None
    db.commit()
    log_action(db, admin, "post_restored", "post", post_id, request=request)
    return _admin_redirect(status_filter, "post-restored")


@router.post("/admin/moderation/comment/{comment_id}/hide")
def hide_comment(
    comment_id: int,
    request: Request,
    reason: str = Form(""),
    report_id: int = Form(0),
    status_filter: str = Form(""),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    comment = db.query(Comment).filter(Comment.id == comment_id).first()
    if comment is None:
        raise HTTPException(status_code=404, detail="Comment not found.")
    comment.is_hidden = True
    comment.hidden_reason = clean_text(reason, 255) or "Hidden by a moderator."
    db.commit()
    log_action(db, admin, "comment_hidden", "comment", comment_id,
               reason=comment.hidden_reason, report_id=report_id or None, request=request)
    return _admin_redirect(status_filter, "comment-hidden")


@router.post("/admin/moderation/comment/{comment_id}/restore")
def restore_comment(
    comment_id: int,
    request: Request,
    status_filter: str = Form(""),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    comment = db.query(Comment).filter(Comment.id == comment_id).first()
    if comment is None:
        raise HTTPException(status_code=404, detail="Comment not found.")
    comment.is_hidden = False
    comment.hidden_reason = None
    db.commit()
    log_action(db, admin, "comment_restored", "comment", comment_id, request=request)
    return _admin_redirect(status_filter, "comment-restored")


@router.post("/admin/moderation/user/{user_id}/suspend")
def suspend_user(
    user_id: int,
    request: Request,
    reason: str = Form(""),
    report_id: int = Form(0),
    status_filter: str = Form(""),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    target = db.query(User).filter(User.id == user_id).first()
    if target is None:
        raise HTTPException(status_code=404, detail="Account not found.")
    if target.id == admin.id:
        raise HTTPException(status_code=400, detail="You cannot suspend your own account.")
    if target.role == "admin":
        # Removing another admin's access is an operator decision (manage.py),
        # not something one admin can do to another through the web UI.
        raise HTTPException(status_code=403, detail="Administrator accounts cannot be suspended here.")
    target.is_suspended = True
    target.suspension_reason = clean_text(reason, 255) or "Suspended by a moderator."
    target.suspended_at = datetime.now(timezone.utc)
    db.commit()
    log_action(db, admin, "user_suspended", "profile", user_id,
               reason=target.suspension_reason, report_id=report_id or None, request=request)
    return _admin_redirect(status_filter, "user-suspended")


@router.post("/admin/moderation/user/{user_id}/reinstate")
def reinstate_user(
    user_id: int,
    request: Request,
    status_filter: str = Form(""),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    target = db.query(User).filter(User.id == user_id).first()
    if target is None:
        raise HTTPException(status_code=404, detail="Account not found.")
    target.is_suspended = False
    target.suspension_reason = None
    target.suspended_at = None
    db.commit()
    log_action(db, admin, "user_reinstated", "profile", user_id, request=request)
    return _admin_redirect(status_filter, "user-reinstated")
