"""Admin panel routes — overview stats and training-example review."""
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, Response, RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.user import User
from app.models.learning import NEEDS_EDIT, REJECTION_REASONS
from app.models.training_example import TrainingExample
from app.services import audit
from app.services.auth_service import require_admin
from app.services.sanitize import clean_text
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

    # Pending training examples awaiting review.
    pending = training_service.get_pending_examples(db)
    pending_count = len(pending)

    return templates.TemplateResponse("admin.html", {
        "request": request,
        "user": user,
        "current_user": user,
        "total_users": total_users,
        "pending_examples": pending,
        "pending_count": pending_count,
    })


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
