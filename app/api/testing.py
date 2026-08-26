"""Testing environment routes — overview, labs, events.

All routes require tester or admin role.
"""
from fastapi import APIRouter, Depends, Request, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.user import User
from app.models.security_event import SecurityEvent
from app.models.training_example import TrainingExample
from app.services.auth_service import require_tester
from app.services.analysis import analyze_lab_submission
from app.labs import list_labs, get_lab
from app.config import settings

router = APIRouter(prefix="/testing", tags=["testing"])
templates = Jinja2Templates(directory="app/templates")


@router.get("", response_class=HTMLResponse)
def testing_overview(
    request: Request,
    user: User = Depends(require_tester),
    db: Session = Depends(get_db),
):
    total_events = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.user_id == user.id
    ).scalar() or 0

    detected_count = db.query(func.count(SecurityEvent.id)).filter(
        SecurityEvent.user_id == user.id,
        SecurityEvent.detection_result == "detected",
    ).scalar() or 0

    pending_knowledge = db.query(func.count(TrainingExample.id)).filter(
        TrainingExample.approved == False
    ).scalar() or 0

    recent_events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.user_id == user.id)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(10)
        .all()
    )

    labs = list_labs()

    return templates.TemplateResponse("testing/overview.html", {
        "request": request,
        "user": user,
        "sentinel_model": settings.SENTINEL_MODEL_NAME,
        "available_labs": len(labs),
        "total_events": total_events,
        "detected_count": detected_count,
        "pending_knowledge": pending_knowledge,
        "recent_events": recent_events,
        "labs": labs,
    })


@router.get("/labs", response_class=HTMLResponse)
def testing_labs(
    request: Request,
    user: User = Depends(require_tester),
):
    labs = list_labs()
    return templates.TemplateResponse("testing/labs.html", {
        "request": request,
        "user": user,
        "labs": labs,
    })


@router.get("/labs/{lab_id}", response_class=HTMLResponse)
def testing_lab_detail(
    lab_id: str,
    request: Request,
    user: User = Depends(require_tester),
):
    lab = get_lab(lab_id)
    if not lab:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

    return templates.TemplateResponse("testing/lab_detail.html", {
        "request": request,
        "user": user,
        "lab": lab,
    })


@router.post("/labs/{lab_id}/submit", response_class=HTMLResponse)
def testing_lab_submit(
    lab_id: str,
    request: Request,
    payload: str = Form(...),
    user: User = Depends(require_tester),
    db: Session = Depends(get_db),
):
    lab = get_lab(lab_id)
    if not lab:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

    # Run the sandboxed lab handler
    handler = lab["handler"]
    lab_result = handler(payload)

    # Run full analysis pipeline
    result = analyze_lab_submission(
        db=db,
        user_id=user.id,
        lab_id=lab_id,
        lab_category=lab["category"],
        payload=payload,
        lab_result=lab_result,
    )

    # If blocked, redirect to block page
    if result["blocked"]:
        return RedirectResponse(
            url=f"/testing/blocked?event_id={result['event_id']}&lab_id={lab_id}",
            status_code=303,
        )

    return templates.TemplateResponse("testing/attack_result.html", {
        "request": request,
        "user": user,
        "result": result,
        "lab_output": lab_result.get("output", ""),
    })


@router.get("/events", response_class=HTMLResponse)
def testing_events(
    request: Request,
    user: User = Depends(require_tester),
    db: Session = Depends(get_db),
):
    events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.user_id == user.id)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(100)
        .all()
    )
    return templates.TemplateResponse("testing/events.html", {
        "request": request,
        "user": user,
        "events": events,
    })


@router.get("/events/{event_id}", response_class=HTMLResponse)
def testing_event_detail(
    event_id: int,
    request: Request,
    user: User = Depends(require_tester),
    db: Session = Depends(get_db),
):
    event = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.id == event_id, SecurityEvent.user_id == user.id)
        .first()
    )
    if not event:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

    return templates.TemplateResponse("testing/event_detail.html", {
        "request": request,
        "user": user,
        "event": event,
    })


@router.get("/blocked", response_class=HTMLResponse)
def testing_blocked(
    request: Request,
    event_id: int = Query(0),
    lab_id: str = Query(""),
    user: User = Depends(require_tester),
    db: Session = Depends(get_db),
):
    event = None
    if event_id:
        event = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.id == event_id, SecurityEvent.user_id == user.id)
            .first()
        )

    return templates.TemplateResponse("testing/blocked.html", {
        "request": request,
        "user": user,
        "event": event,
        "lab_id": lab_id,
    })
