"""Testing environment routes — overview, labs, sessions, events.

This whole area is private. Every route depends on `require_lab_access`, so
an anonymous or suspended request never reaches a handler — the gate is the
dependency, not a hidden nav link. Any authenticated account in good standing
may use the labs; the labs themselves stay sandboxed (in-memory fixtures, no
shell, no filesystem, no outbound network) and only ever target this
application.
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, Form, Query, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.user import User
from app.models.lab_session import LabSession
from app.models.learning import (
    CANDIDATE, EXAMPLE_STATUS_LABELS, FEEDBACK_VERDICTS, FEEDBACK_VERDICT_LABELS,
    AnalysisFeedback,
)
from app.models.security_event import SecurityEvent
from app.models.training_example import TrainingExample
from app.services import audit
from app.services import training as training_service
from app.services.auth_service import require_lab_access
from app.services.analysis import analyze_lab_submission, record_analysis_feedback
from app.services.ratelimit import limit_analysis, limit_feedback
from app.services.sanitize import clean_text
from app.services.scoring import BAND_LABELS
from app.labs import list_labs, get_lab
from app.config import settings
from app.template_env import templates

router = APIRouter(prefix="/testing", tags=["testing"])


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------

@router.get("", response_class=HTMLResponse)
def testing_overview(
    request: Request,
    user: User = Depends(require_lab_access),
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
        TrainingExample.status == CANDIDATE
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
# Analysis layer — Sentinel status, collected knowledge, dataset/training state
#
# All three are read-only and scoped to the requesting account. Promotion,
# export, and cross-user views live behind `require_admin` in app/api/admin.py;
# nothing here can change a candidate's status.
# ---------------------------------------------------------------------------

@router.get("/sentinel", response_class=HTMLResponse)
def testing_sentinel(
    request: Request,
    user: User = Depends(require_lab_access),
    db: Session = Depends(get_db),
):
    """What the CyberLLM analysis layer is, and what it just said about your
    own submissions.

    Deliberately honest about capability: with no inference endpoint configured
    the analysis is the deterministic local analyzer built from the detection
    engine's own findings, not a served neural model.
    """
    recent_events = (
        db.query(SecurityEvent)
        .filter(
            SecurityEvent.user_id == user.id,
            SecurityEvent.detection_result == "detected",
        )
        .order_by(SecurityEvent.timestamp.desc())
        .limit(15)
        .all()
    )
    return templates.TemplateResponse("testing/sentinel.html", {
        "request": request,
        "user": user,
        "sentinel_model": settings.SENTINEL_MODEL_NAME,
        "endpoint_configured": bool(settings.CYBERLLM_API_URL),
        "recent_events": recent_events,
    })


@router.get("/knowledge", response_class=HTMLResponse)
def testing_knowledge(
    request: Request,
    user: User = Depends(require_lab_access),
    db: Session = Depends(get_db),
):
    """Training candidates collected from *this* account's own lab activity.

    Read-only: a user sees what their submissions produced and how the scorer
    triaged it, but only an admin can approve, reject, or export.
    """
    examples = training_service.examples_for_user(db, user.id, limit=50)
    return templates.TemplateResponse("testing/knowledge.html", {
        "request": request,
        "user": user,
        "sentinel_model": settings.SENTINEL_MODEL_NAME,
        "examples": examples,
        "band_labels": BAND_LABELS,
        "status_labels": EXAMPLE_STATUS_LABELS,
    })


@router.get("/training", response_class=HTMLResponse)
def testing_training(
    request: Request,
    user: User = Depends(require_lab_access),
    db: Session = Depends(get_db),
):
    """Dataset/training state: how the pipeline stands overall.

    Counts are global (the dataset is a shared asset) but every mutating action
    — approve, export, freeze — stays admin-only. The page states plainly that
    nothing trains automatically and the eval split never trains.
    """
    status_counts = training_service.status_counts(db)
    band_counts = training_service.band_counts(db)
    train_ready = len(training_service.get_approved_examples(db, split="train"))
    eval_ready = len(training_service.get_approved_examples(db, split="eval"))
    return templates.TemplateResponse("testing/training.html", {
        "request": request,
        "user": user,
        "sentinel_model": settings.SENTINEL_MODEL_NAME,
        "status_counts": status_counts,
        "status_labels": EXAMPLE_STATUS_LABELS,
        "band_counts": band_counts,
        "band_labels": BAND_LABELS,
        "train_ready": train_ready,
        "eval_ready": eval_ready,
        "is_admin": user.is_admin,
    })


# ---------------------------------------------------------------------------
# Labs
# ---------------------------------------------------------------------------

@router.get("/labs", response_class=HTMLResponse)
def testing_labs(
    request: Request,
    user: User = Depends(require_lab_access),
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
    user: User = Depends(require_lab_access),
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
    audit.record(db, "testing.session_started", user=user,
                 target_type="lab_session", target_id=session.session_id,
                 detail=f"lab={lab_id}", request=request)

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


@router.post("/labs/{lab_id}/submit", response_class=HTMLResponse,
             dependencies=[Depends(limit_analysis)])
def testing_lab_submit(
    lab_id: str,
    request: Request,
    payload: str = Form(...),
    session_id: str = Form(""),
    user: User = Depends(require_lab_access),
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
            audit.record(db, "testing.session_ended", user=user,
                         target_type="lab_session", target_id=session.session_id,
                         detail=f"blocked: {result.get('attack_type', 'unknown')}",
                         request=request)
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
    user: User = Depends(require_lab_access),
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
    user: User = Depends(require_lab_access),
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
    user: User = Depends(require_lab_access),
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
    user: User = Depends(require_lab_access),
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
    user: User = Depends(require_lab_access),
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

    # This account's own verdict on the explanation, if it has given one.
    feedback = (
        db.query(AnalysisFeedback)
        .filter(
            AnalysisFeedback.event_id == event.id,
            AnalysisFeedback.user_id == user.id,
        )
        .first()
    )

    return templates.TemplateResponse("testing/event_detail.html", {
        "request": request,
        "user": user,
        "event": event,
        "session": session,
        "feedback": feedback,
        "feedback_verdicts": FEEDBACK_VERDICTS,
        "feedback_verdict_labels": FEEDBACK_VERDICT_LABELS,
        "sentinel_model": settings.SENTINEL_MODEL_NAME,
    })


@router.post("/events/{event_id}/feedback",
             dependencies=[Depends(limit_feedback)])
def testing_event_feedback(
    event_id: int,
    request: Request,
    verdict: str = Form(...),
    note: str = Form(""),
    user: User = Depends(require_lab_access),
    db: Session = Depends(get_db),
):
    """Record this user's verdict on an event's analysis.

    Scoped to the caller's own event (an unknown or someone else's event is a
    404, never a silent write), one verdict per (event, user). The verdict is a
    signal for reviewers; it cannot approve, reject, or train anything.
    """
    if verdict not in FEEDBACK_VERDICTS:
        raise HTTPException(status_code=400, detail="Unknown feedback verdict.")

    event = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.id == event_id, SecurityEvent.user_id == user.id)
        .first()
    )
    if not event:
        raise HTTPException(status_code=404, detail="Event not found.")

    record_analysis_feedback(
        db, event, user.id, verdict, note=clean_text(note, 500) or None,
    )
    audit.record(db, "analysis.feedback", user=user,
                 target_type="security_event", target_id=str(event_id),
                 detail=f"verdict={verdict}", request=request)
    return RedirectResponse(url=f"/testing/events/{event_id}", status_code=303)


# ---------------------------------------------------------------------------
# Blocked (legacy — kept for sessions without a session_id)
# ---------------------------------------------------------------------------

@router.get("/blocked", response_class=HTMLResponse)
def testing_blocked(
    request: Request,
    event_id: int = Query(0),
    lab_id: str = Query(""),
    user: User = Depends(require_lab_access),
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
