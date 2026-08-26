"""Admin panel routes — stats, event review, training example management."""
import json
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, Response, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.user import User
from app.models.security_event import SecurityEvent
from app.models.training_example import TrainingExample
from app.services.auth_service import require_admin
from app.services import training as training_service

router = APIRouter(prefix="/admin", tags=["admin"])
templates = Jinja2Templates(directory="app/templates")


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
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    training_service.approve_example(db, example_id, user.id)
    return RedirectResponse(url="/admin", status_code=303)


@router.post("/training/{example_id}/reject")
def reject_training(
    example_id: int,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    training_service.reject_example(db, example_id)
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
