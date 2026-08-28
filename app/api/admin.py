"""Admin panel routes — stats, event review, training example management."""
import json
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, Response, RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.user import User
from app.models.security_event import SecurityEvent
from app.models.training_example import TrainingExample
from app.services import audit
from app.services.auth_service import require_admin
from app.services.sanitize import clean_text
from app.services import training as training_service
from app.template_env import templates

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("", response_class=HTMLResponse)
def admin_dashboard(
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    total_users = db.query(func.count(User.id)).scalar() or 0
    total_attacks = db.query(func.count(SecurityEvent.id)).scalar() or 0

    successful = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.success == True
    ).scalar() or 0

    blocked = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.blocked == True
    ).scalar() or 0

    # Attacks by category
    category_counts = (
        db.query(SecurityEvent.attack_category, func.count(SecurityEvent.id))
        .filter(SecurityEvent.detection_result == "detected")
        .group_by(SecurityEvent.attack_category)
        .all()
    )
    categories = {cat: count for cat, count in category_counts}

    # Recent events
    recent_events = (
        db.query(SecurityEvent)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(20)
        .all()
    )

    # Pending training examples
    pending = training_service.get_pending_examples(db)
    pending_count = len(pending)

    return templates.TemplateResponse("admin.html", {
        "request": request,
        "user": user,
        "total_users": total_users,
        "total_attacks": total_attacks,
        "successful": successful,
        "blocked": blocked,
        "categories": categories,
        "recent_events": recent_events,
        "pending_examples": pending,
        "pending_count": pending_count,
    })


@router.get("/events/{event_id}", response_class=HTMLResponse)
def admin_event_detail(
    event_id: int,
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if not event:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

    raw_json = None
    if event.raw_analysis_json:
        try:
            raw_json = json.loads(event.raw_analysis_json)
        except json.JSONDecodeError:
            pass

    return templates.TemplateResponse("admin_event.html", {
        "request": request,
        "user": user,
        "event": event,
        "raw_json": raw_json,
    })


@router.post("/training/{example_id}/approve")
def approve_training(
    example_id: int,
    request: Request,
    note: str = Form(""),
    label: str = Form(""),
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
    return RedirectResponse(url="/admin", status_code=303)


@router.post("/training/{example_id}/reject")
def reject_training(
    example_id: int,
    request: Request,
    reason: str = Form("other"),
    note: str = Form(""),
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
    return RedirectResponse(url="/admin", status_code=303)


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
