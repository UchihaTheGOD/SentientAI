"""Likes, comments, bookmarks, follows and notifications.

The interesting assertions here are the ownership ones. Every button in these
flows is only *rendered* for the person entitled to press it, which is worth
nothing on its own — so each test posts to the route directly as the wrong user
and expects the server to refuse.
"""
from __future__ import annotations

import pytest

from app.models.blog_post import POST_DRAFT, POST_PUBLISHED, BlogPost
from app.models.social import Bookmark, Comment, Follow, Notification, PostLike
from tests.conftest import Client


@pytest.fixture
def post(db, user):
    """A published post owned by the `user` fixture."""
    row = BlogPost(
        slug="social-fixture-post",
        title="Social fixture post",
        author=user.display,
        user_id=user.id,
        category="Technology",
        summary="A summary.",
        content="A body with enough words in it to look like a real post.",
        reading_time=1,
    )
    row.apply_state(POST_PUBLISHED)
    db.add(row)
    db.commit()
    db.refresh(row)
    yield row


def _comment(db, post, author, body="A perfectly ordinary comment.", **kwargs):
    row = Comment(user_id=author.id, post_id=post.id, body=body, **kwargs)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


# ---------------------------------------------------------------------------
# Likes
# ---------------------------------------------------------------------------

def test_like_requires_sign_in(client, post):
    response = client.post(f"/blog/{post.slug}/like", {"value": "1"})
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")


def test_like_then_same_vote_again_removes_it(other_client, db, post, other_user):
    first = other_client.post(f"/blog/{post.slug}/like", {"value": "1"})
    assert first.status_code == 303
    assert db.query(PostLike).filter(
        PostLike.post_id == post.id, PostLike.user_id == other_user.id,
    ).count() == 1

    other_client.post(f"/blog/{post.slug}/like", {"value": "1"})
    assert db.query(PostLike).filter(
        PostLike.post_id == post.id, PostLike.user_id == other_user.id,
    ).count() == 0


def test_switching_from_like_to_dislike_replaces_the_vote(other_client, db, post, other_user):
    other_client.post(f"/blog/{post.slug}/like", {"value": "1"})
    other_client.post(f"/blog/{post.slug}/like", {"value": "-1"})

    votes = db.query(PostLike).filter(
        PostLike.post_id == post.id, PostLike.user_id == other_user.id,
    ).all()
    assert len(votes) == 1
    assert votes[0].value == -1


def test_a_vote_value_outside_plus_minus_one_is_rejected(other_client, db, post):
    response = other_client.post(f"/blog/{post.slug}/like", {"value": "500"})
    assert response.status_code == 400
    assert db.query(PostLike).filter(PostLike.post_id == post.id).count() == 0


def test_liking_your_own_post_creates_no_notification(auth_client, db, post, user):
    auth_client.post(f"/blog/{post.slug}/like", {"value": "1"})
    assert db.query(Notification).filter(Notification.user_id == user.id).count() == 0


def test_someone_elses_like_notifies_the_author(other_client, db, post, user):
    other_client.post(f"/blog/{post.slug}/like", {"value": "1"})
    notification = (
        db.query(Notification)
        .filter(Notification.user_id == user.id, Notification.notif_type == "like")
        .first()
    )
    assert notification is not None
    assert notification.is_read is False


def test_an_unpublished_post_cannot_be_liked(other_client, db, post):
    post.apply_state(POST_DRAFT)
    db.commit()
    assert other_client.post(f"/blog/{post.slug}/like", {"value": "1"}).status_code == 404


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------

def test_comment_requires_sign_in(client, post):
    response = client.post(f"/blog/{post.slug}/comment", {"body": "Hello"})
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")


def test_comment_is_stored_and_notifies_the_author(other_client, db, post, user):
    response = other_client.post(f"/blog/{post.slug}/comment", {
        "body": "This is a comment from someone else.",
    })
    assert response.status_code == 303

    comment = db.query(Comment).filter(Comment.post_id == post.id).first()
    assert comment is not None
    assert comment.body == "This is a comment from someone else."
    assert db.query(Notification).filter(
        Notification.user_id == user.id, Notification.notif_type == "comment",
    ).count() == 1


def test_an_empty_comment_is_not_stored(auth_client, db, post):
    response = auth_client.post(f"/blog/{post.slug}/comment", {"body": "   "})
    assert response.status_code == 303
    assert db.query(Comment).filter(Comment.post_id == post.id).count() == 0


def test_replies_are_flattened_to_one_level(auth_client, db, post, user):
    parent = _comment(db, post, user, "Top level.")
    reply = _comment(db, post, user, "First reply.", parent_id=parent.id)

    auth_client.post(f"/blog/{post.slug}/comment", {
        "body": "A reply to the reply.", "parent_id": str(reply.id),
    })
    deepest = db.query(Comment).order_by(Comment.id.desc()).first()
    # Attached to the top-level comment, not to the reply.
    assert deepest.parent_id == parent.id


def test_a_reply_to_a_comment_on_another_post_is_ignored(auth_client, db, post, user):
    other_post = BlogPost(
        slug="unrelated-post", title="Unrelated", author="Someone",
        category="Technology", summary="", content="Body text here.", reading_time=1,
    )
    other_post.apply_state(POST_PUBLISHED)
    db.add(other_post)
    db.commit()
    foreign = _comment(db, other_post, user, "On a different post.")

    auth_client.post(f"/blog/{post.slug}/comment", {
        "body": "Trying to graft onto another post's thread.",
        "parent_id": str(foreign.id),
    })
    created = db.query(Comment).filter(Comment.post_id == post.id).first()
    assert created is not None
    assert created.parent_id is None


def test_only_the_author_can_edit_a_comment(other_client, db, post, user):
    comment = _comment(db, post, user)
    response = other_client.post(
        f"/blog/{post.slug}/comment/{comment.id}/edit", {"body": "Rewritten by someone else."},
    )
    assert response.status_code == 403

    db.expire_all()
    assert db.query(Comment).filter(Comment.id == comment.id).first().body == \
        "A perfectly ordinary comment."


def test_an_admin_cannot_rewrite_someone_elses_comment(admin_client, db, post, user):
    comment = _comment(db, post, user)
    response = admin_client.post(
        f"/blog/{post.slug}/comment/{comment.id}/edit", {"body": "Admin edit."},
    )
    # Admins may hide a comment; they may not put words in someone's mouth.
    assert response.status_code == 403


def test_the_author_can_edit_their_own_comment(auth_client, db, post, user):
    comment = _comment(db, post, user)
    response = auth_client.post(
        f"/blog/{post.slug}/comment/{comment.id}/edit", {"body": "Edited by me."},
    )
    assert response.status_code == 303

    db.expire_all()
    updated = db.query(Comment).filter(Comment.id == comment.id).first()
    assert updated.body == "Edited by me."


def test_only_the_author_or_an_admin_can_delete_a_comment(other_client, db, post, user):
    comment = _comment(db, post, user)
    assert other_client.post(
        f"/blog/{post.slug}/comment/{comment.id}/delete", {},
    ).status_code == 403

    db.expire_all()
    assert db.query(Comment).filter(Comment.id == comment.id).first().is_deleted is False


def test_deleting_a_comment_is_a_soft_delete(auth_client, db, post, user):
    comment = _comment(db, post, user)
    response = auth_client.post(f"/blog/{post.slug}/comment/{comment.id}/delete", {})
    assert response.status_code == 303

    db.expire_all()
    row = db.query(Comment).filter(Comment.id == comment.id).first()
    # The row survives so a report about it can still be reviewed.
    assert row is not None
    assert row.is_deleted is True

    page = auth_client.get(f"/blog/{post.slug}")
    assert "A perfectly ordinary comment." not in page.text


def test_a_deleted_comment_can_no_longer_be_edited(auth_client, db, post, user):
    comment = _comment(db, post, user, is_deleted=True)
    response = auth_client.post(
        f"/blog/{post.slug}/comment/{comment.id}/edit", {"body": "Sneaking an edit in."},
    )
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Bookmarks
# ---------------------------------------------------------------------------

def test_bookmark_toggles_and_appears_on_the_bookmarks_page(auth_client, db, post, user):
    assert auth_client.post(f"/blog/{post.slug}/bookmark", {}).status_code == 303
    assert db.query(Bookmark).filter(
        Bookmark.user_id == user.id, Bookmark.post_id == post.id,
    ).count() == 1

    page = auth_client.get("/bookmarks")
    assert page.status_code == 200
    assert post.title in page.text

    auth_client.post(f"/blog/{post.slug}/bookmark", {})
    assert db.query(Bookmark).filter(Bookmark.user_id == user.id).count() == 0


def test_a_bookmarked_post_that_is_unpublished_drops_out_of_the_list(auth_client, db, post):
    auth_client.post(f"/blog/{post.slug}/bookmark", {})
    post.apply_state(POST_DRAFT)
    db.commit()

    page = auth_client.get("/bookmarks")
    assert page.status_code == 200
    assert post.title not in page.text


def test_one_users_bookmarks_are_invisible_to_another(other_client, auth_client, db, post):
    auth_client.post(f"/blog/{post.slug}/bookmark", {})
    page = other_client.get("/bookmarks")
    assert page.status_code == 200
    assert post.title not in page.text


# ---------------------------------------------------------------------------
# Follows
# ---------------------------------------------------------------------------

def test_follow_and_unfollow(other_client, db, user, other_user):
    assert other_client.post(f"/users/{user.username}/follow", {}).status_code == 303
    assert db.query(Follow).filter(
        Follow.follower_id == other_user.id, Follow.followed_id == user.id,
    ).count() == 1
    assert db.query(Notification).filter(
        Notification.user_id == user.id, Notification.notif_type == "follow",
    ).count() == 1

    other_client.post(f"/users/{user.username}/follow", {})
    assert db.query(Follow).filter(Follow.follower_id == other_user.id).count() == 0


def test_you_cannot_follow_yourself(auth_client, db, user):
    response = auth_client.post(f"/users/{user.username}/follow", {})
    assert response.status_code == 400
    assert db.query(Follow).filter(Follow.follower_id == user.id).count() == 0


def test_following_an_unknown_user_is_a_404(auth_client):
    assert auth_client.post("/users/nobody-here/follow", {}).status_code == 404


def test_follow_requires_sign_in(client, user):
    response = client.post(f"/users/{user.username}/follow", {})
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

def _notify(db, recipient, actor):
    row = Notification(
        user_id=recipient.id, actor_id=actor.id, notif_type="like",
        message="Something happened.", target_url="/",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def test_opening_the_page_does_not_mark_everything_read(auth_client, db, user, other_user):
    notification = _notify(db, user, other_user)
    assert auth_client.get("/notifications").status_code == 200

    db.expire_all()
    # Deliberate: coming back to something later has to stay possible.
    assert db.query(Notification).filter(
        Notification.id == notification.id,
    ).first().is_read is False


def test_marking_one_notification_read(auth_client, db, user, other_user):
    notification = _notify(db, user, other_user)
    response = auth_client.post(f"/notifications/{notification.id}/read", {})
    assert response.status_code == 303

    db.expire_all()
    assert db.query(Notification).filter(Notification.id == notification.id).first().is_read


def test_marking_all_notifications_read(auth_client, db, user, other_user):
    _notify(db, user, other_user)
    _notify(db, user, other_user)
    assert auth_client.post("/notifications/read-all", {}).status_code == 303

    db.expire_all()
    unread = db.query(Notification).filter(
        Notification.user_id == user.id, Notification.is_read == False,  # noqa: E712
    ).count()
    assert unread == 0


def test_you_cannot_mark_someone_elses_notification_read(other_client, db, user, other_user):
    notification = _notify(db, user, other_user)
    response = other_client.post(f"/notifications/{notification.id}/read", {})
    assert response.status_code == 404

    db.expire_all()
    assert db.query(Notification).filter(
        Notification.id == notification.id,
    ).first().is_read is False


def test_read_all_only_touches_your_own_notifications(other_client, db, user, other_user):
    mine = _notify(db, user, other_user)
    theirs = _notify(db, other_user, user)
    other_client.post("/notifications/read-all", {})

    db.expire_all()
    assert db.query(Notification).filter(Notification.id == theirs.id).first().is_read is True
    assert db.query(Notification).filter(Notification.id == mine.id).first().is_read is False
