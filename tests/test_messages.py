"""Direct messaging: sending, the inbox, threads, read-state, and access.

These pin the rules that matter for a private chat feature: only signed-in users
reach it, you can't message yourself or a suspended account, bodies are stored as
plain text, a message notifies the recipient, and reading a thread clears its
unread count for the reader only.
"""
from __future__ import annotations

import pytest

from app.models.message import Message
from app.models.social import Notification
from app.models.user import User
from app.services import messaging


# ---------------------------------------------------------------------------
# Service layer
# ---------------------------------------------------------------------------

def test_send_message_persists_and_notifies(db, user, other_user):
    msg = messaging.send_message(db, user, other_user, "  Hello there!  ")

    assert msg.id is not None
    assert msg.sender_id == user.id
    assert msg.recipient_id == other_user.id
    assert msg.pair_key == messaging.pair_key(user.id, other_user.id)
    # Stored as plain text the sender typed (collapsed), never HTML.
    assert msg.body == "Hello there!"
    assert msg.is_read is False

    notif = (
        db.query(Notification)
        .filter(Notification.user_id == other_user.id,
                Notification.notif_type == "message")
        .first()
    )
    assert notif is not None
    assert notif.target_url == f"/messages/{user.username}"


def test_you_cannot_message_yourself(db, user):
    with pytest.raises(ValueError):
        messaging.send_message(db, user, user, "hi me")


def test_you_cannot_message_a_suspended_account(db, user, other_user):
    target = db.query(User).filter(User.id == other_user.id).first()
    target.is_suspended = True
    db.commit()
    with pytest.raises(ValueError):
        messaging.send_message(db, user, target, "hello")
    assert db.query(Message).count() == 0


def test_an_empty_message_is_rejected(db, user, other_user):
    with pytest.raises(ValueError):
        messaging.send_message(db, user, other_user, "    ")


def test_thread_is_ordered_and_shared_by_both_sides(db, user, other_user):
    messaging.send_message(db, user, other_user, "first")
    messaging.send_message(db, other_user, user, "second")

    a = messaging.get_thread(db, user, other_user)
    b = messaging.get_thread(db, other_user, user)
    assert [m.body for m in a] == ["first", "second"]
    assert [m.id for m in a] == [m.id for m in b]  # same conversation


def test_inbox_groups_by_person_newest_first(db, user, other_user, admin):
    messaging.send_message(db, other_user, user, "hey")
    messaging.send_message(db, admin, user, "yo")          # newer, different person
    messaging.send_message(db, other_user, user, "again")  # newest overall

    convos = messaging.list_conversations(db, user)
    # One entry per person, most-recent conversation first.
    assert [c["user"].id for c in convos] == [other_user.id, admin.id]
    assert convos[0]["preview"] == "again"
    assert convos[0]["unread"] == 2  # two unread from other_user


def test_reading_a_thread_clears_only_the_readers_unread(db, user, other_user):
    messaging.send_message(db, other_user, user, "unread please")
    assert messaging.unread_count(db, user.id) == 1

    cleared = messaging.mark_thread_read(db, user, other_user)
    assert cleared == 1
    assert messaging.unread_count(db, user.id) == 0
    # The sender's own view is unaffected.
    assert messaging.unread_count(db, other_user.id) == 0


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

def test_sending_through_the_route_redirects_to_the_thread(auth_client, other_user, db):
    resp = auth_client.post(f"/messages/{other_user.username}", {"body": "Hi via route"})
    assert resp.status_code == 303
    assert resp.headers["location"] == f"/messages/{other_user.username}"
    assert db.query(Message).filter(Message.body == "Hi via route").count() == 1


def test_the_recipient_sees_the_conversation(auth_client, other_client, other_user, user):
    auth_client.post(f"/messages/{other_user.username}", {"body": "knock knock"})
    page = other_client.get(f"/messages/{user.username}")
    assert page.status_code == 200
    assert "knock knock" in page.text


def test_an_empty_body_is_rejected_by_the_route(auth_client, other_user, db):
    resp = auth_client.post(f"/messages/{other_user.username}", {"body": "   "})
    assert resp.status_code == 400
    assert db.query(Message).count() == 0


def test_messaging_yourself_redirects_to_the_inbox(auth_client, user):
    resp = auth_client.get(f"/messages/{user.username}")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/messages"


def test_messaging_a_missing_user_is_404(auth_client):
    assert auth_client.get("/messages/nobody-here").status_code == 404


def test_anonymous_users_cannot_reach_messages(client):
    # Not signed in → the auth dependency rejects it (never a 200 inbox).
    assert client.get("/messages").status_code != 200


def test_send_requires_csrf(auth_client, other_user, db):
    resp = auth_client.post(f"/messages/{other_user.username}", {"body": "no token"}, csrf=False)
    assert resp.status_code == 403
    assert db.query(Message).count() == 0
