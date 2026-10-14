"""Direct messaging routes — inbox, one conversation, and sending.

Server-rendered chat: no websockets. Every route requires a signed-in user
(`get_current_user` is a real dependency, not a cookie sniff), sending is rate
limited, and a message is only ever sent through `app.services.messaging`, which
sanitises the body and enforces who may message whom.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.services import messaging
from app.services.auth_service import get_current_user
from app.services.ratelimit import limit_message
from app.template_env import templates

router = APIRouter(tags=["messages"])


def _other_or_404(db: Session, username: str) -> User:
    other = db.query(User).filter(User.username == username).first()
    if other is None:
        raise HTTPException(status_code=404, detail="No such person.")
    return other


@router.get("/messages", response_class=HTMLResponse)
def inbox(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return templates.TemplateResponse("messages_inbox.html", {
        "request": request,
        "current_user": user,
        "conversations": messaging.list_conversations(db, user),
    })


@router.get("/messages/{username}", response_class=HTMLResponse)
def thread(
    username: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    other = _other_or_404(db, username)
    if other.id == user.id:
        return RedirectResponse(url="/messages", status_code=303)
    messaging.mark_thread_read(db, user, other)
    return templates.TemplateResponse("messages_thread.html", {
        "request": request,
        "current_user": user,
        "other": other,
        "messages": messaging.get_thread(db, user, other),
        "error": None,
    })


@router.post("/messages/{username}", dependencies=[Depends(limit_message)])
def send(
    username: str,
    request: Request,
    body: str = Form(""),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    other = _other_or_404(db, username)
    try:
        messaging.send_message(db, user, other, body)
    except ValueError as exc:
        # Re-render the conversation with the reason, keeping the typed text
        # visible so nothing is lost.
        return templates.TemplateResponse("messages_thread.html", {
            "request": request,
            "current_user": user,
            "other": other,
            "messages": messaging.get_thread(db, user, other),
            "error": str(exc),
            "draft": body,
        }, status_code=400)
    return RedirectResponse(url=f"/messages/{other.username}", status_code=303)
