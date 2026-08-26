"""User-facing routes — dashboard, profile."""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.user import User
from app.models.security_event import SecurityEvent
from app.services.auth_service import get_current_user
from app.labs import list_labs

router = APIRouter(tags=["users"])
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # User stats
    total_attacks = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.user_id == user.id
    ).scalar() or 0

    detected = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.user_id == user.id,
        SecurityEvent.detection_result == "detected",
    ).scalar() or 0

    successful = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.user_id == user.id,
        SecurityEvent.success == True,
    ).scalar() or 0

    blocked = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.user_id == user.id,
        SecurityEvent.blocked == True,
    ).scalar() or 0

    # Recent activity
    recent_events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.user_id == user.id)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(10)
        .all()
    )

    labs = list_labs()

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "stats": {
            "total_attacks": total_attacks,
            "detected": detected,
            "successful": successful,
            "blocked": blocked,
        },
        "recent_events": recent_events,
        "labs": labs,
    })


@router.get("/profile", response_class=HTMLResponse)
def profile(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    total = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.user_id == user.id
    ).scalar() or 0

    return templates.TemplateResponse("profile.html", {
        "request": request,
        "user": user,
        "total_attacks": total,
    })
