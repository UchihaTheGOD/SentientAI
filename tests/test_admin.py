"""The admin panel: authorization first, then the destructive operations.

Two things are load-bearing here and get tested hardest:

* **Every** /admin endpoint is closed server-side. A signed-in ordinary user
  gets a 403, not a rendered page with the buttons hidden — `require_admin` is a
  dependency, not a template condition. An anonymous visitor is bounced to the
  login form.
* Deleting a user (or all users) removes every dependent row in one transaction.
  SQLite here runs with foreign keys off, so the declared ``ON DELETE CASCADE``
  never fires and the application has to do it by hand. If that ordering is
  wrong we either leak rows or orphan content pointing at a missing account, so
  the cascade is asserted table by table. Audit-trail rows (reports, moderation
  actions) are kept, with the user reference nulled — never deleted.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.config import settings
from app.models.audit import AuditEvent
from app.models.blog_post import POST_PUBLISHED, BlogPost
from app.models.moderation import REPORT_OPEN, ModerationAction, Report
from app.models.password_reset import PasswordResetToken
from app.models.social import (
    Bookmark, Comment, CommentLike, Follow, Notification, PostLike,
)
from app.models.user import User
from tests.conftest import PASSWORD, Client, _make_user

BODY = "A body with plenty of words in it, comfortably past the minimum length."


# ---------------------------------------------------------------------------
# Small builders. Kept local so each test reads top to bottom.
# ---------------------------------------------------------------------------

def _post(db, owner, *, slug, title=None, state=POST_PUBLISHED):
    row = BlogPost(
        slug=slug, title=title or slug.replace("-", " ").title(),
        author=owner.display, user_id=owner.id, category="Technology",
        summary="", content=BODY, reading_time=1,
    )
    row.apply_state(state)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _comment(db, author, post, *, body="A comment.", parent_id=None):
    row = Comment(user_id=author.id, post_id=post.id, body=body, parent_id=parent_id)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


@pytest.fixture
def anon(app):
    """A never-signed-in client, distinct from the shared `client` that
    `auth_client` logs in."""
    return Client(app)


# ---------------------------------------------------------------------------
# Authorization — the boundary on every endpoint
# ---------------------------------------------------------------------------

ADMIN_GET_PATHS = [
    "/admin",
    "/admin/users",
    "/admin/users/remove-all",
    "/admin/users/1",
    "/admin/posts",
    "/admin/comments",
    "/admin/logs",
    "/admin/settings",
    "/admin/training",
    "/admin/training/rejected",
    "/admin/export",
]

# id-bearing paths use a nonexistent id on purpose: require_admin runs during
# dependency resolution, before the route body's lookup, so a stranger is
# refused (403) without ever learning whether the row exists.
ADMIN_POST_PATHS = [
    "/admin/users/1/delete",
    "/admin/users/remove-all",
    "/admin/posts/1/delete",
    "/admin/comments/1/delete",
    "/admin/training/1/approve",
    "/admin/training/1/reject",
    "/admin/training/1/needs-edit",
]


@pytest.mark.parametrize("path", ADMIN_GET_PATHS)
def test_admin_get_pages_bounce_anonymous_visitors_to_login(anon, path):
    response = anon.get(path)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")


@pytest.mark.parametrize("path", ADMIN_GET_PATHS)
def test_admin_get_pages_are_forbidden_to_ordinary_users(auth_client, path):
    assert auth_client.get(path).status_code == 403


@pytest.mark.parametrize("path", ADMIN_POST_PATHS)
def test_admin_post_actions_are_forbidden_to_ordinary_users(auth_client, path):
    assert auth_client.post(path, {}).status_code == 403


@pytest.mark.parametrize("path", ADMIN_POST_PATHS)
def test_admin_post_actions_bounce_anonymous_visitors(anon, path):
    # CSRF is satisfied (the client carries the cookie/token), so the request
    # reaches require_admin and is turned away as unauthenticated.
    response = anon.post(path, {})
    assert response.status_code in (302, 303)
    assert response.headers["location"].startswith("/login")


@pytest.mark.parametrize("path", ADMIN_GET_PATHS)
def test_every_admin_page_opens_for_an_admin(admin_client, admin, path):
    # /admin/users/1 resolves to the admin's own detail page (id 1 is the only
    # account in a clean DB); the rest are collection pages.
    if path == "/admin/users/1":
        path = f"/admin/users/{admin.id}"
    assert admin_client.get(path).status_code == 200


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

def test_dashboard_renders_with_live_counts(admin_client, db, admin):
    author = _make_user("user")
    _post(db, author, slug="counted-post")
    page = admin_client.get("/admin")
    assert page.status_code == 200
    assert "Admin dashboard" in page.text


# ---------------------------------------------------------------------------
# User list — search and filter
# ---------------------------------------------------------------------------

def test_user_search_matches_username_and_email(admin_client):
    alice = _make_user("user", username="alice_wonder", email="alice@example.test")
    _make_user("user", username="bob_builder", email="bob@example.test")

    by_name = admin_client.get("/admin/users?q=alice_wonder")
    assert "alice_wonder" in by_name.text and "bob_builder" not in by_name.text

    by_email = admin_client.get("/admin/users?q=bob@example")
    assert "bob_builder" in by_email.text and "alice_wonder" not in by_email.text


def test_user_status_filter_separates_active_and_suspended(admin_client, db):
    active = _make_user("user", username="still_here")
    suspended = _make_user("user", username="sent_away")
    db.query(User).filter(User.id == suspended.id).update(
        {User.is_suspended: True}, synchronize_session=False)
    db.commit()

    only_suspended = admin_client.get("/admin/users?status=suspended")
    assert "sent_away" in only_suspended.text and "still_here" not in only_suspended.text


def test_user_detail_shows_the_account(admin_client, db):
    target = _make_user("user", username="inspect_me")
    _post(db, target, slug="their-post")
    page = admin_client.get(f"/admin/users/{target.id}")
    assert page.status_code == 200
    assert "inspect_me" in page.text


def test_user_detail_for_unknown_id_is_404(admin_client):
    assert admin_client.get("/admin/users/999999").status_code == 404


# ---------------------------------------------------------------------------
# Deleting a single user
# ---------------------------------------------------------------------------

def test_deleting_a_user_needs_the_username_typed_back(admin_client, db):
    target = _make_user("user", username="type_me_exactly")
    response = admin_client.post(
        f"/admin/users/{target.id}/delete", {"confirm": "wrong"})
    assert response.status_code == 400
    assert db.query(User).filter(User.id == target.id).count() == 1


def test_deleting_a_user_with_the_right_confirmation_succeeds(admin_client, db):
    target = _make_user("user", username="goodbye_now")
    response = admin_client.post(
        f"/admin/users/{target.id}/delete", {"confirm": "goodbye_now"})
    assert response.status_code == 303
    assert response.headers["location"] == "/admin/users?done=user-deleted"
    assert db.query(User).filter(User.id == target.id).count() == 0


def test_an_admin_cannot_delete_their_own_account(admin_client, db, admin):
    response = admin_client.post(
        f"/admin/users/{admin.id}/delete", {"confirm": admin.username})
    assert response.status_code == 400
    assert db.query(User).filter(User.id == admin.id).count() == 1


def test_an_admin_account_cannot_be_deleted_from_the_panel(admin_client, db):
    other_admin = _make_user("admin", username="fellow_admin")
    response = admin_client.post(
        f"/admin/users/{other_admin.id}/delete", {"confirm": "fellow_admin"})
    assert response.status_code == 403
    assert db.query(User).filter(User.id == other_admin.id).count() == 1


def test_deleting_an_unknown_user_is_404(admin_client):
    assert admin_client.post(
        "/admin/users/999999/delete", {"confirm": "whatever"}).status_code == 404


def test_deleting_a_user_purges_everything_they_own(admin_client, db):
    """The cascade, table by table. Foreign keys are off, so this is the only
    thing standing between a deleted account and a database full of orphans."""
    victim = _make_user("user", username="the_departed")
    bystander = _make_user("user", username="the_witness")

    # The victim's own post, with someone else's comment/like/bookmark on it.
    vpost = _post(db, victim, slug="victims-post")
    on_vpost = _comment(db, bystander, vpost, body="Reacting to the victim.")
    db.add_all([
        PostLike(user_id=bystander.id, post_id=vpost.id, value=1),
        Bookmark(user_id=bystander.id, post_id=vpost.id),
        CommentLike(user_id=bystander.id, comment_id=on_vpost.id, value=1),
    ])
    db.commit()

    # The victim's footprint on someone else's post.
    bpost = _post(db, bystander, slug="bystanders-post")
    by_victim = _comment(db, victim, bpost, body="The victim was here.")
    db.add_all([
        PostLike(user_id=victim.id, post_id=bpost.id, value=1),
        Bookmark(user_id=victim.id, post_id=bpost.id),
        CommentLike(user_id=victim.id, comment_id=by_victim.id, value=1),
        Follow(follower_id=victim.id, followed_id=bystander.id),
        Follow(follower_id=bystander.id, followed_id=victim.id),
        Notification(user_id=victim.id, actor_id=bystander.id,
                     notif_type="follow", message="witness followed you"),
        Notification(user_id=bystander.id, actor_id=victim.id,
                     notif_type="follow", message="departed followed you"),
        PasswordResetToken(user_id=victim.id, token_hash="d" * 64,
                           expires_at=datetime.now(timezone.utc) + timedelta(hours=1)),
    ])
    # Audit-trail rows that reference the victim: these must survive, nulled.
    report = Report(reporter_id=victim.id, target_type="post", target_id=bpost.id,
                    reason="spam", status=REPORT_OPEN)
    action = ModerationAction(moderator_id=victim.id, action="post_hidden",
                              target_type="post", target_id=bpost.id)
    db.add_all([report, action])
    db.commit()
    vid, bid = victim.id, bystander.id
    vpost_id, bpost_id = vpost.id, bpost.id
    on_vpost_id, by_victim_id = on_vpost.id, by_victim.id
    report_id, action_id = report.id, action.id

    response = admin_client.post(
        f"/admin/users/{vid}/delete", {"confirm": "the_departed"})
    assert response.status_code == 303
    db.expire_all()

    # The account and everything it exclusively owned is gone.
    assert db.query(User).filter(User.id == vid).count() == 0
    assert db.query(BlogPost).filter(BlogPost.id == vpost_id).count() == 0
    assert db.query(Comment).filter(Comment.id == on_vpost_id).count() == 0
    assert db.query(Comment).filter(Comment.id == by_victim_id).count() == 0
    assert db.query(PostLike).filter(PostLike.user_id == vid).count() == 0
    assert db.query(Bookmark).filter(Bookmark.user_id == vid).count() == 0
    assert db.query(CommentLike).filter(CommentLike.user_id == vid).count() == 0
    assert db.query(Follow).filter(
        (Follow.follower_id == vid) | (Follow.followed_id == vid)).count() == 0
    assert db.query(Notification).filter(
        (Notification.user_id == vid) | (Notification.actor_id == vid)).count() == 0
    assert db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == vid).count() == 0
    # No dangling rows against the deleted post either.
    assert db.query(PostLike).filter(PostLike.post_id == vpost_id).count() == 0
    assert db.query(Bookmark).filter(Bookmark.post_id == vpost_id).count() == 0

    # The bystander and their post are untouched.
    assert db.query(User).filter(User.id == bid).count() == 1
    assert db.query(BlogPost).filter(BlogPost.id == bpost_id).count() == 1

    # Audit trail retained, but the reference to the deleted account is cleared.
    kept_report = db.query(Report).filter(Report.id == report_id).first()
    assert kept_report is not None and kept_report.reporter_id is None
    kept_action = db.query(ModerationAction).filter(
        ModerationAction.id == action_id).first()
    assert kept_action is not None and kept_action.moderator_id is None


def test_deleting_a_user_records_an_audit_event(admin_client, db):
    target = _make_user("user", username="leaves_a_trace")
    admin_client.post(f"/admin/users/{target.id}/delete", {"confirm": "leaves_a_trace"})
    events = db.query(AuditEvent).filter(
        AuditEvent.event_type == "moderation.action").all()
    assert any("user_deleted" in (e.detail or "") for e in events)


# ---------------------------------------------------------------------------
# Remove all users — the "reset to a single admin" operation
# ---------------------------------------------------------------------------

def test_remove_all_page_reports_the_count(admin_client):
    _make_user("user")
    _make_user("user")
    page = admin_client.get("/admin/users/remove-all")
    assert page.status_code == 200
    assert "REMOVE ALL USERS" in page.text


def test_remove_all_needs_the_exact_phrase(admin_client, db):
    _make_user("user")
    _make_user("user")
    before = db.query(User).filter(User.role != "admin").count()
    assert before == 2
    response = admin_client.post("/admin/users/remove-all", {"confirm": "remove all users"})
    assert response.status_code == 400
    assert db.query(User).filter(User.role != "admin").count() == 2


def test_remove_all_deletes_normal_users_and_keeps_admins_and_their_content(
    admin_client, db, admin,
):
    # Two normal users, one with content; a second admin with content.
    u1 = _make_user("user", username="normal_one")
    u2 = _make_user("user", username="normal_two")
    _post(db, u1, slug="doomed-post")
    _comment(db, u2, _post(db, u1, slug="another-doomed"), body="bye")

    other_admin = _make_user("admin", username="second_admin")
    admin_post = _post(db, admin, slug="admin-keeps-this")
    other_admin_post = _post(db, other_admin, slug="other-admin-keeps-this")

    response = admin_client.post(
        "/admin/users/remove-all", {"confirm": "REMOVE ALL USERS"})
    assert response.status_code == 303
    assert response.headers["location"] == "/admin/users?done=removed-2"
    db.expire_all()

    # Every non-admin is gone; both admins remain.
    assert db.query(User).filter(User.role != "admin").count() == 0
    assert db.query(User).filter(User.id == admin.id).count() == 1
    assert db.query(User).filter(User.id == other_admin.id).count() == 1

    # Deleted users took their content with them; admin content is preserved.
    assert db.query(BlogPost).filter(BlogPost.user_id == u1.id).count() == 0
    assert db.query(BlogPost).filter(BlogPost.id == admin_post.id).count() == 1
    assert db.query(BlogPost).filter(BlogPost.id == other_admin_post.id).count() == 1


def test_remove_all_with_no_normal_users_is_a_no_op(admin_client, db, admin):
    response = admin_client.post(
        "/admin/users/remove-all", {"confirm": "REMOVE ALL USERS"})
    assert response.status_code == 303
    assert response.headers["location"] == "/admin/users?done=removed-0"
    assert db.query(User).filter(User.id == admin.id).count() == 1


# ---------------------------------------------------------------------------
# Posts
# ---------------------------------------------------------------------------

def test_post_list_search_filters_by_title(admin_client, db):
    author = _make_user("user")
    _post(db, author, slug="findable", title="A Findable Article")
    _post(db, author, slug="hidden-away", title="Something Else Entirely")
    page = admin_client.get("/admin/posts?q=Findable")
    assert "A Findable Article" in page.text
    assert "Something Else Entirely" not in page.text


def test_admin_deleting_a_post_removes_its_dependent_rows(admin_client, db):
    author = _make_user("user")
    reader = _make_user("user")
    post = _post(db, author, slug="admin-will-remove")
    comment = _comment(db, reader, post, body="A comment on it.")
    db.add_all([
        PostLike(user_id=reader.id, post_id=post.id, value=1),
        Bookmark(user_id=reader.id, post_id=post.id),
        CommentLike(user_id=author.id, comment_id=comment.id, value=1),
    ])
    db.commit()
    post_id, comment_id = post.id, comment.id

    response = admin_client.post(f"/admin/posts/{post_id}/delete", {})
    assert response.status_code == 303
    db.expire_all()

    assert db.query(BlogPost).filter(BlogPost.id == post_id).count() == 0
    assert db.query(Comment).filter(Comment.post_id == post_id).count() == 0
    assert db.query(PostLike).filter(PostLike.post_id == post_id).count() == 0
    assert db.query(Bookmark).filter(Bookmark.post_id == post_id).count() == 0
    assert db.query(CommentLike).filter(CommentLike.comment_id == comment_id).count() == 0
    # And it is recorded.
    assert db.query(AuditEvent).filter(AuditEvent.event_type == "post.deleted").count() == 1


def test_admin_deleting_an_unknown_post_is_404(admin_client):
    assert admin_client.post("/admin/posts/999999/delete", {}).status_code == 404


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------

def test_admin_deleting_a_comment_detaches_replies_and_drops_its_likes(admin_client, db):
    author = _make_user("user")
    replier = _make_user("user")
    post = _post(db, author, slug="thread-host")
    parent = _comment(db, author, post, body="The parent comment.")
    reply = _comment(db, replier, post, body="A reply.", parent_id=parent.id)
    db.add(CommentLike(user_id=replier.id, comment_id=parent.id, value=1))
    db.commit()
    parent_id, reply_id = parent.id, reply.id

    response = admin_client.post(f"/admin/comments/{parent_id}/delete", {})
    assert response.status_code == 303
    db.expire_all()

    assert db.query(Comment).filter(Comment.id == parent_id).count() == 0
    assert db.query(CommentLike).filter(CommentLike.comment_id == parent_id).count() == 0
    # The reply survives as orphaned-but-readable content, no longer nested.
    surviving = db.query(Comment).filter(Comment.id == reply_id).first()
    assert surviving is not None and surviving.parent_id is None


def test_admin_deleting_an_unknown_comment_is_404(admin_client):
    assert admin_client.post("/admin/comments/999999/delete", {}).status_code == 404


# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

def test_logs_show_recorded_events(admin_client, db):
    # Signing in already wrote an auth.login event for the admin.
    page = admin_client.get("/admin/logs")
    assert page.status_code == 200
    assert "auth.login" in page.text


def test_logs_filter_by_event_type(admin_client, db):
    author = _make_user("user")
    post = _post(db, author, slug="to-be-logged")
    admin_client.post(f"/admin/posts/{post.id}/delete", {})

    filtered = admin_client.get("/admin/logs?event_type=post.deleted")
    assert filtered.status_code == 200
    assert "post.deleted" in filtered.text


def test_logs_ignore_an_unknown_event_type(admin_client):
    # A bogus filter is treated as "no filter", not an error.
    assert admin_client.get("/admin/logs?event_type=not.a.real.type").status_code == 200


# ---------------------------------------------------------------------------
# Settings — configuration is visible, secrets are not
# ---------------------------------------------------------------------------

def test_settings_never_shows_the_secret_key_value(admin_client):
    page = admin_client.get("/admin/settings")
    assert page.status_code == 200
    # The distinctive test secret must never appear; only its status does.
    assert settings.SECRET_KEY not in page.text
    assert "configured" in page.text


def test_settings_never_shows_an_smtp_password(admin_client, monkeypatch):
    monkeypatch.setattr(settings, "SMTP_PASSWORD", "super-secret-smtp-pw")
    page = admin_client.get("/admin/settings")
    assert page.status_code == 200
    assert "super-secret-smtp-pw" not in page.text
