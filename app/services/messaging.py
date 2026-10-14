"""Direct messaging between users.

The public-facing chat feature. Everything a route needs lives here so the API
layer stays thin: validation, sanitising, the conversation/inbox grouping, and
the read-state bookkeeping. Message bodies are stored as the plain text the
sender typed (via ``clean_text``) and rendered escaped by Jinja — never as HTML.

A message to someone also drops a normal in-app notification, so the recipient
sees it in the bell badge and on ``/notifications`` like any other activity.
"""
from __future__ import annotations

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.message import Message
from app.models.social import Notification
from app.models.user import User
from app.services.sanitize import clean_text, strip_formatting

MAX_MESSAGE = 2000
MIN_MESSAGE = 1


def pair_key(a: int, b: int) -> str:
    """Order-independent conversation key for two user ids."""
    lo, hi = (a, b) if a <= b else (b, a)
    return f"{lo}:{hi}"


def send_message(db: Session, sender: User, recipient: User, body: str) -> Message:
    """Persist one message from ``sender`` to ``recipient``.

    Raises ``ValueError`` (with a user-safe message) when the send is not
    allowed, so the route can re-render the compose box with the reason.
    """
    if recipient is None:
        raise ValueError("That account no longer exists.")
    if recipient.id == sender.id:
        raise ValueError("You can't message yourself.")
    if not recipient.can_sign_in:
        raise ValueError("You can't message this account right now.")

    text = clean_text(body, MAX_MESSAGE)
    if len(text.strip()) < MIN_MESSAGE:
        raise ValueError("Write a message first.")

    message = Message(
        sender_id=sender.id,
        recipient_id=recipient.id,
        pair_key=pair_key(sender.id, recipient.id),
        body=text,
    )
    db.add(message)

    db.add(Notification(
        user_id=recipient.id,
        actor_id=sender.id,
        notif_type="message",
        message=f"{sender.display} sent you a message",
        target_url=f"/messages/{sender.username}",
    ))
    db.commit()
    db.refresh(message)
    return message


def list_conversations(db: Session, user: User) -> list[dict]:
    """One entry per person ``user`` has exchanged messages with, newest first.

    Each entry carries the other participant, the latest message, and how many
    messages in that thread are unread for ``user``. Volume is personal-scale,
    so the newest-per-thread grouping is done in Python rather than in SQL.
    """
    rows = (
        db.query(Message)
        .filter(or_(Message.sender_id == user.id, Message.recipient_id == user.id))
        .order_by(Message.created_at.desc())
        .all()
    )
    if not rows:
        return []

    unread_by_sender: dict[int, int] = {}
    for m in rows:
        if m.recipient_id == user.id and not m.is_read:
            unread_by_sender[m.sender_id] = unread_by_sender.get(m.sender_id, 0) + 1

    latest: dict[int, Message] = {}
    order: list[int] = []
    for m in rows:  # already newest-first
        other_id = m.sender_id if m.recipient_id == user.id else m.recipient_id
        if other_id not in latest:
            latest[other_id] = m
            order.append(other_id)

    others = {
        u.id: u for u in db.query(User).filter(User.id.in_(order)).all()
    }

    conversations = []
    for other_id in order:
        other = others.get(other_id)
        if other is None:  # account gone
            continue
        last = latest[other_id]
        conversations.append({
            "user": other,
            "preview": strip_formatting(last.body, 120),
            "last_at": last.created_at,
            "unread": unread_by_sender.get(other_id, 0),
            "outgoing": last.sender_id == user.id,
        })
    return conversations


def get_thread(db: Session, user: User, other: User) -> list[Message]:
    """Every message between ``user`` and ``other``, oldest first."""
    return (
        db.query(Message)
        .filter(Message.pair_key == pair_key(user.id, other.id))
        .order_by(Message.created_at.asc())
        .all()
    )


def mark_thread_read(db: Session, user: User, other: User) -> int:
    """Mark messages ``other`` sent to ``user`` as read. Returns how many."""
    updated = (
        db.query(Message)
        .filter(
            Message.recipient_id == user.id,
            Message.sender_id == other.id,
            Message.is_read == False,  # noqa: E712
        )
        .update({Message.is_read: True}, synchronize_session=False)
    )
    if updated:
        db.commit()
    return updated


def unread_count(db: Session, user_id: int) -> int:
    """Total unread messages for the header badge."""
    return (
        db.query(Message)
        .filter(Message.recipient_id == user_id, Message.is_read == False)  # noqa: E712
        .count()
    )
