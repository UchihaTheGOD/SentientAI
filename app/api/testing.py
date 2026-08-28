"""Testing environment routes — overview, labs, sessions, events.

All routes require tester or admin role.
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.user import User
from app.models.lab_session import LabSession
from app.models.security_event import SecurityEvent
from app.models.training_example import TrainingExample
from app.services.auth_service import require_tester
from app.services.analysis import analyze_lab_submission
from app.labs import list_labs, get_lab
from app.config import settings

router = APIRouter(prefix="/testing", tags=["testing"])
templates = Jinja2Templates(directory="app/templates")


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------

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

    active_sessions = db.query(func.count(LabSession.id)).filter(
        LabSession.user_id == user.id,
        LabSession.status == "active",
    ).scalar() or 0

    recent_events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.user_id == user.id)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(10)
        .all()
    )

    recent_sessions = (
        db.query(LabSession)
        .filter(LabSession.user_id == user.id)
        .order_by(LabSession.started_at.desc())
        .limit(5)
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
        "active_sessions": active_sessions,
        "recent_events": recent_events,
        "recent_sessions": recent_sessions,
        "labs": labs,
    })


# ---------------------------------------------------------------------------
# Labs
# ---------------------------------------------------------------------------

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
    db: Session = Depends(get_db),
):
    lab = get_lab(lab_id)
    if not lab:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

    # Create a new session for this lab visit
    session = LabSession(
        user_id=user.id,
        lab_id=lab_id,
        status="active",
        started_at=datetime.now(timezone.utc),
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    # Use the realistic target template for xss_stored; generic form for others
    if lab_id == "xss_stored":
        template_name = "testing/target_xss_stored.html"
    else:
        template_name = "testing/lab_detail.html"

    return templates.TemplateResponse(template_name, {
        "request": request,
        "user": user,
        "lab": lab,
        "session": session,
        "sentinel_model": settings.SENTINEL_MODEL_NAME,
    })


@router.post("/labs/{lab_id}/submit", response_class=HTMLResponse)
def testing_lab_submit(
    lab_id: str,
    request: Request,
    payload: str = Form(...),
    session_id: str = Form(""),
    user: User = Depends(require_tester),
    db: Session = Depends(get_db),
):
    lab = get_lab(lab_id)
    if not lab:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

    # Resolve session
    session = None
    if session_id:
        session = (
            db.query(LabSession)
            .filter(
                LabSession.session_id == session_id,
                LabSession.user_id == user.id,
            )
            .first()
        )

    # If session is terminated/completed, block further submissions
    if session and not session.is_active:
        return RedirectResponse(
            url=f"/testing/session-ended/{session.session_id}",
            status_code=303,
        )

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
        session_id=session.session_id if session else None,
    )

    # Update session counters
    if session:
        session.attack_count = (session.attack_count or 0) + 1
        if result["detected"]:
            session.detected_count = (session.detected_count or 0) + 1
        if result["blocked"]:
            session.blocked_count = (session.blocked_count or 0) + 1

        # Terminate session on block
        if result["blocked"]:
            session.status = "terminated"
            session.ended_at = datetime.now(timezone.utc)
            session.termination_reason = (
                f"Critical payload detected: {result.get('attack_type', 'Unknown attack')}. "
                f"Severity: {result.get('severity', 'unknown')}."
            )

        db.add(session)
        db.commit()

        if result["blocked"]:
            return RedirectResponse(
                url=f"/testing/session-ended/{session.session_id}",
                status_code=303,
            )
    else:
        # Legacy path — no session, use old blocked redirect
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
        "session": session,
        "sentinel_model": settings.SENTINEL_MODEL_NAME,
    })


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

@router.get("/sessions", response_class=HTMLResponse)
def testing_sessions_list(
    request: Request,
    user: User = Depends(require_tester),
    db: Session = Depends(get_db),
):
    sessions = (
        db.query(LabSession)
        .filter(LabSession.user_id == user.id)
        .order_by(LabSession.started_at.desc())
        .limit(50)
        .all()
    )
    return templates.TemplateResponse("testing/sessions_list.html", {
        "request": request,
        "user": user,
        "sessions": sessions,
        "sentinel_model": settings.SENTINEL_MODEL_NAME,
    })


@router.get("/sessions/{session_id}", response_class=HTMLResponse)
def testing_session_timeline(
    session_id: str,
    request: Request,
    user: User = Depends(require_tester),
    db: Session = Depends(get_db),
):
    session = (
        db.query(LabSession)
        .filter(
            LabSession.session_id == session_id,
            LabSession.user_id == user.id,
        )
        .first()
    )
    if not session:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

    events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.session_id == session_id)
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    )

    lab = get_lab(session.lab_id)

    return templates.TemplateResponse("testing/session_timeline.html", {
        "request": request,
        "user": user,
        "session": session,
        "events": events,
        "lab": lab,
        "sentinel_model": settings.SENTINEL_MODEL_NAME,
    })


@router.get("/session-ended/{session_id}", response_class=HTMLResponse)
def testing_session_ended(
    session_id: str,
    request: Request,
    user: User = Depends(require_tester),
    db: Session = Depends(get_db),
):
    session = (
        db.query(LabSession)
        .filter(
            LabSession.session_id == session_id,
            LabSession.user_id == user.id,
        )
        .first()
    )
    if not session:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

    events = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.session_id == session_id)
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    )

    # Find the triggering (blocked/most severe) event
    trigger_event = None
    for ev in events:
        if ev.blocked:
            trigger_event = ev
            break
    if not trigger_event and events:
        trigger_event = events[-1]

    lab = get_lab(session.lab_id)

    return templates.TemplateResponse("testing/session_ended.html", {
        "request": request,
        "user": user,
        "session": session,
        "events": events,
        "trigger_event": trigger_event,
        "lab": lab,
        "sentinel_model": settings.SENTINEL_MODEL_NAME,
    })


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

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
        "sentinel_model": settings.SENTINEL_MODEL_NAME,
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

    # Load parent session if linked
    session = None
    if event.session_id:
        session = (
            db.query(LabSession)
            .filter(LabSession.session_id == event.session_id)
            .first()
        )

    return templates.TemplateResponse("testing/event_detail.html", {
        "request": request,
        "user": user,
        "event": event,
        "session": session,
        "sentinel_model": settings.SENTINEL_MODEL_NAME,
    })


# ---------------------------------------------------------------------------
# Blocked (legacy — kept for sessions without a session_id)
# ---------------------------------------------------------------------------

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
        "sentinel_model": settings.SENTINEL_MODEL_NAME,
    })
