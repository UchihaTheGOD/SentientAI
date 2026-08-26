"""Attack history and blocked page routes."""
from fastapi import APIRouter, Depends, Request, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.models.security_event import SecurityEvent
from app.services.auth_service import get_current_user

router = APIRouter(tags=["attacks"])
templates = Jinja2Templates(directory="app/templates")


@router.get("/attacks", response_class=HTMLResponse)
def attack_history(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.user_id == user.id)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(100)
        .all()
    )
    return templates.TemplateResponse("attacks.html", {
        "request": request,
        "user": user,
        "events": events,
    })


@router.get("/attacks/{event_id}", response_class=HTMLResponse)
def attack_detail(
    event_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    event = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.id == event_id, SecurityEvent.user_id == user.id)
        .first()
    )
    if not event:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

    return templates.TemplateResponse("attack_detail.html", {
        "request": request,
        "user": user,
        "event": event,
    })


@router.get("/blocked", response_class=HTMLResponse)
def blocked_page(
    request: Request,
    event_id: int = Query(0),
    lab_id: str = Query(""),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    event = None
    if event_id:
        event = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.id == event_id, SecurityEvent.user_id == user.id)
            .first()
        )

    return templates.TemplateResponse("blocked.html", {
        "request": request,
        "user": user,
        "event": event,
        "lab_id": lab_id,
    })
