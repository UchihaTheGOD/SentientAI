"""Reporting and moderation: two tiers, enforced server-side.

Every admin route is hit here as an ordinary signed-in user as well as an
admin, because "the button isn't rendered" is not access control. The other
thing worth pinning down is that moderation is reversible and recorded: hiding
sets a flag rather than deleting, and each decision leaves a `ModerationAction`
row behind.
"""
from __future__ import annotations

import pytest

from app.models.audit import AuditEvent
from app.models.blog_post import POST_PUBLISHED, BlogPost
from app.models.moderation import (
    REPORT_DISMISSED,
    REPORT_OPEN,
    REPORT_RESOLVED,
    ModerationAction,
    Report,
)
from app.models.social import Comment
from app.models.user import User
from tests.conftest import Client, _make_user

BODY = "A body with plenty of words in it, comfortably past the minimum length."


@pytest.fixture
def post(db, other_user):
    row = BlogPost(
        slug="reportable-post", title="Reportable post", author=other_user.display,
        user_id=other_user.id, category="Technology", summary="",
        content=BODY, reading_time=1,
    )
    row.apply_state(POST_PUBLISHED)
    db.add(row)
    db.commit()
    db.refresh(row)
    yield row


@pytest.fixture
def comment(db, post, other_user):
    row = Comment(user_id=other_user.id, post_id=post.id, body="A reportable comment.")
    db.add(row)
    db.commit()
    db.refresh(row)
    yield row


@pytest.fixture
def anon(app):
    """A never-signed-in client, separate from the shared `client` fixture that
    `auth_client` logs in."""
    yield Client(app)


ADMIN_GET_PATHS = ["/admin/moderation", "/admin"]


# ---------------------------------------------------------------------------
# Tier boundaries
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", ADMIN_GET_PATHS)
def test_admin_pages_are_closed_to_anonymous_visitors(client, path):
    response = client.get(path)
    assert response.status_code in (303, 401, 403)


@pytest.mark.parametrize("path", ADMIN_GET_PATHS)
def test_admin_pages_are_closed_to_ordinary_signed_in_users(auth_client, path):
    # Signed in is not the same as authorized — this is the whole point of
    # `require_admin` being a dependency rather than a template condition.
    assert auth_client.get(path).status_code == 403


def test_the_queue_opens_for_an_admin(admin_client):
    assert admin_client.get("/admin/moderation").status_code == 200


@pytest.mark.parametrize("path_template", [
    "/admin/moderation/{report}/resolve",
    "/admin/moderation/{report}/dismiss",
])
def test_report_decisions_are_closed_to_ordinary_users(
    auth_client, db, post, user, path_template,
):
    report = Report(reporter_id=user.id, target_type="post", target_id=post.id,
                    reason="spam", status=REPORT_OPEN)
    db.add(report)
    db.commit()
    db.refresh(report)

    path = path_template.format(report=report.id)
    assert auth_client.post(path, {"note": "letting myself through"}).status_code == 403

    db.expire_all()
    assert db.query(Report).filter(Report.id == report.id).first().status == REPORT_OPEN


def test_content_actions_are_closed_to_ordinary_users(auth_client, db, post, comment):
    attempts = [
        (f"/admin/moderation/post/{post.id}/hide", {"reason": "because I said so"}),
        (f"/admin/moderation/post/{post.id}/restore", {}),
        (f"/admin/moderation/comment/{comment.id}/hide", {"reason": "no"}),
        (f"/admin/moderation/comment/{comment.id}/restore", {}),
    ]
    for path, payload in attempts:
        assert auth_client.post(path, payload).status_code == 403, path

    db.expire_all()
    assert db.query(BlogPost).filter(BlogPost.id == post.id).first().is_hidden is False
    assert db.query(Comment).filter(Comment.id == comment.id).first().is_hidden is False


def test_suspension_is_closed_to_ordinary_users(auth_client, db, other_user):
    response = auth_client.post(
        f"/admin/moderation/user/{other_user.id}/suspend", {"reason": "personal grudge"},
    )
    assert response.status_code == 403

    db.expire_all()
    assert db.query(User).filter(User.id == other_user.id).first().is_suspended is False


# ---------------------------------------------------------------------------
# Reporting — any signed-in user
# ---------------------------------------------------------------------------

def test_reporting_requires_sign_in(anon, post):
    response = anon.get(f"/report?type=post&id={post.id}")
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")


def test_the_report_form_renders_for_a_signed_in_user(auth_client, post):
    page = auth_client.get(f"/report?type=post&id={post.id}")
    assert page.status_code == 200
    assert post.title in page.text


def test_reporting_something_that_does_not_exist_is_a_404(auth_client):
    assert auth_client.get("/report?type=post&id=999999").status_code == 404


def test_an_unknown_target_type_is_refused(auth_client, post):
    response = auth_client.post("/report", {
        "target_type": "spaceship", "target_id": str(post.id),
        "reason": "spam", "details": "",
    })
    assert response.status_code == 400


def test_a_reason_outside_the_list_is_refused(auth_client, db, post):
    response = auth_client.post("/report", {
        "target_type": "post", "target_id": str(post.id),
        "reason": "i-just-dont-like-it", "details": "",
    })
    assert response.status_code == 400
    assert db.query(Report).count() == 0


def test_a_report_lands_in_the_queue(auth_client, db, post, user):
    response = auth_client.post("/report", {
        "target_type": "post", "target_id": str(post.id),
        "reason": "spam", "details": "This is advertising.",
    })
    assert response.status_code == 200

    report = db.query(Report).filter(Report.target_id == post.id).first()
    assert report is not None
    assert report.reporter_id == user.id
    assert report.status == REPORT_OPEN
    assert report.reason == "spam"
    # A snapshot of what was reported, so the queue survives a later edit.
    assert report.target_label == post.title


def test_reporting_the_same_thing_twice_does_not_duplicate(auth_client, db, post):
    payload = {"target_type": "post", "target_id": str(post.id),
               "reason": "spam", "details": ""}
    auth_client.post("/report", payload)
    auth_client.post("/report", payload)
    assert db.query(Report).filter(Report.target_id == post.id).count() == 1


def test_report_details_are_stored_as_flattened_text(auth_client, db, post):
    auth_client.post("/report", {
        "target_type": "post", "target_id": str(post.id), "reason": "spam",
        "details": "line one\nline two\ttabbed",
    })
    report = db.query(Report).filter(Report.target_id == post.id).first()
    assert report.details == "line one line two tabbed"


# ---------------------------------------------------------------------------
# Acting on a report
# ---------------------------------------------------------------------------

def _report(db, reporter, target_type, target_id, reason="spam"):
    row = Report(reporter_id=reporter.id, target_type=target_type,
                 target_id=target_id, reason=reason, status=REPORT_OPEN)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def test_an_admin_can_resolve_a_report_and_it_is_recorded(
    admin_client, db, post, user, admin,
):
    report = _report(db, user, "post", post.id)
    response = admin_client.post(
        f"/admin/moderation/{report.id}/resolve", {"note": "Content removed."},
    )
    assert response.status_code == 303

    db.expire_all()
    row = db.query(Report).filter(Report.id == report.id).first()
    assert row.status == REPORT_RESOLVED
    assert row.resolved_by == admin.id
    assert row.resolved_at is not None
    assert row.resolution_note == "Content removed."

    action = db.query(ModerationAction).filter(
        ModerationAction.report_id == report.id,
    ).first()
    assert action is not None
    assert action.action == "report_resolved"
    assert action.moderator_id == admin.id


def test_an_admin_can_dismiss_a_report(admin_client, db, post, user):
    report = _report(db, user, "post", post.id)
    assert admin_client.post(
        f"/admin/moderation/{report.id}/dismiss", {"note": "Nothing wrong here."},
    ).status_code == 303

    db.expire_all()
    assert db.query(Report).filter(Report.id == report.id).first().status == REPORT_DISMISSED


def test_acting_on_an_unknown_report_is_a_404(admin_client):
    assert admin_client.post("/admin/moderation/999999/resolve", {}).status_code == 404


# ---------------------------------------------------------------------------
# Hiding and restoring
# ---------------------------------------------------------------------------

def test_hiding_a_post_removes_it_from_public_view_reversibly(
    admin_client, anon, db, post,
):
    assert anon.get(f"/blog/{post.slug}").status_code == 200

    assert admin_client.post(
        f"/admin/moderation/post/{post.id}/hide", {"reason": "Spam."},
    ).status_code == 303

    db.expire_all()
    row = db.query(BlogPost).filter(BlogPost.id == post.id).first()
    assert row.is_hidden is True
    assert row.hidden_reason == "Spam."
    # Hidden, not deleted: the content is still there to review.
    assert row.content == BODY
    assert anon.get(f"/blog/{post.slug}").status_code == 404

    assert admin_client.post(
        f"/admin/moderation/post/{post.id}/restore", {},
    ).status_code == 303
    db.expire_all()
    assert db.query(BlogPost).filter(BlogPost.id == post.id).first().is_hidden is False
    assert anon.get(f"/blog/{post.slug}").status_code == 200


def test_hiding_a_post_without_a_reason_still_records_one(admin_client, db, post):
    admin_client.post(f"/admin/moderation/post/{post.id}/hide", {"reason": "   "})
    db.expire_all()
    assert db.query(BlogPost).filter(
        BlogPost.id == post.id,
    ).first().hidden_reason == "Hidden by a moderator."


def test_a_hidden_post_disappears_from_listings(admin_client, anon, db, post, other_user):
    admin_client.post(f"/admin/moderation/post/{post.id}/hide", {"reason": "Spam."})
    # Every listing has to agree with the post page. Filtering on `published`
    # alone used to leave hidden posts on /explore, /search and /community.
    paths = (
        "/blog", "/explore", "/", "/community",
        f"/users/{other_user.username}", "/search?q=Reportable&kind=posts",
    )
    for path in paths:
        response = anon.get(path)
        assert response.status_code in (200, 404), path
        assert post.title not in response.text, path


def test_a_hidden_post_is_out_of_a_followers_feed(admin_client, app, db, post, other_user):
    follower = _make_user("user")
    follower_client = Client(app)
    assert follower_client.login(follower.username).status_code == 303
    assert follower_client.post(f"/users/{other_user.username}/follow", {}).status_code == 303
    assert post.title in follower_client.get("/feed").text

    admin_client.post(f"/admin/moderation/post/{post.id}/hide", {"reason": "Spam."})
    assert post.title not in follower_client.get("/feed").text


def test_hiding_a_comment_hides_it_from_the_post_page(admin_client, anon, db, post, comment):
    page = anon.get(f"/blog/{post.slug}")
    assert comment.body in page.text

    assert admin_client.post(
        f"/admin/moderation/comment/{comment.id}/hide", {"reason": "Abusive."},
    ).status_code == 303

    db.expire_all()
    assert db.query(Comment).filter(Comment.id == comment.id).first().is_hidden is True
    assert comment.body not in anon.get(f"/blog/{post.slug}").text

    admin_client.post(f"/admin/moderation/comment/{comment.id}/restore", {})
    assert comment.body in anon.get(f"/blog/{post.slug}").text


def test_hiding_something_that_does_not_exist_is_a_404(admin_client):
    assert admin_client.post(
        "/admin/moderation/post/999999/hide", {"reason": "x"},
    ).status_code == 404
    assert admin_client.post(
        "/admin/moderation/comment/999999/hide", {"reason": "x"},
    ).status_code == 404


# ---------------------------------------------------------------------------
# Suspension
# ---------------------------------------------------------------------------

def test_suspension_blocks_sign_in_and_is_reversible(admin_client, app, db, other_user):
    victim = Client(app)
    assert victim.login(other_user.username).status_code == 303
    victim.logout()

    assert admin_client.post(
        f"/admin/moderation/user/{other_user.id}/suspend", {"reason": "Repeated spam."},
    ).status_code == 303

    db.expire_all()
    row = db.query(User).filter(User.id == other_user.id).first()
    assert row.is_suspended is True
    assert row.suspension_reason == "Repeated spam."
    assert row.suspended_at is not None

    blocked = Client(app).login(other_user.username)
    assert blocked.status_code == 400
    assert "suspended" in blocked.text.lower()

    assert admin_client.post(
        f"/admin/moderation/user/{other_user.id}/reinstate", {},
    ).status_code == 303
    assert Client(app).login(other_user.username).status_code == 303


def test_an_admin_cannot_suspend_their_own_account(admin_client, db, admin):
    response = admin_client.post(
        f"/admin/moderation/user/{admin.id}/suspend", {"reason": "oops"},
    )
    assert response.status_code == 400

    db.expire_all()
    assert db.query(User).filter(User.id == admin.id).first().is_suspended is False


def test_one_admin_cannot_suspend_another(admin_client, db):
    other_admin = _make_user("admin")
    response = admin_client.post(
        f"/admin/moderation/user/{other_admin.id}/suspend", {"reason": "turf war"},
    )
    assert response.status_code == 403

    db.expire_all()
    assert db.query(User).filter(User.id == other_admin.id).first().is_suspended is False


def test_suspending_an_unknown_account_is_a_404(admin_client):
    assert admin_client.post(
        "/admin/moderation/user/999999/suspend", {"reason": "x"},
    ).status_code == 404


# ---------------------------------------------------------------------------
# Auditability
# ---------------------------------------------------------------------------

def test_every_moderation_decision_writes_an_audit_event(admin_client, db, post, comment):
    admin_client.post(f"/admin/moderation/post/{post.id}/hide", {"reason": "Spam."})
    admin_client.post(f"/admin/moderation/comment/{comment.id}/hide", {"reason": "Abuse."})

    events = db.query(AuditEvent).filter(AuditEvent.event_type == "moderation.action").all()
    assert len(events) == 2
    actions = db.query(ModerationAction).all()
    assert {a.action for a in actions} == {"post_hidden", "comment_hidden"}
    # The reason is part of the record, not just the UI.
    assert all(a.reason for a in actions)


def test_a_suspended_user_cannot_report_or_comment(admin_client, app, db, other_user, post):
    victim = Client(app)
    assert victim.login(other_user.username).status_code == 303
    admin_client.post(
        f"/admin/moderation/user/{other_user.id}/suspend", {"reason": "Spam."},
    )

    # Still holding a valid cookie; the account may no longer act.
    assert victim.post("/report", {
        "target_type": "post", "target_id": str(post.id), "reason": "spam", "details": "",
    }).status_code == 403
    assert victim.post(f"/blog/{post.slug}/comment", {"body": "Still here."}).status_code == 403
    assert db.query(Comment).filter(Comment.body == "Still here.").count() == 0
