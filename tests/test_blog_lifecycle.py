"""Post lifecycle: draft, published, archived, hidden, deleted.

Draft privacy is the claim worth testing hardest. A draft is not merely absent
from listings — a signed-in stranger who guesses its slug gets a 404, and the
same 404 an unknown slug produces, so the page's existence is not confirmed.
"""
from __future__ import annotations

import pytest

from app.models.blog_post import (
    BLOG_CATEGORIES,
    POST_ARCHIVED,
    POST_DRAFT,
    POST_PUBLISHED,
    RESEARCH_CATEGORIES,
    BlogPost,
)
from app.models.social import Bookmark, Comment, CommentLike, PostLike
from tests.conftest import Client

BODY = "A body with plenty of words in it, comfortably past the minimum length."


@pytest.fixture
def other_client(app, other_user):
    client = Client(app)
    assert client.login(other_user.username).status_code == 303
    yield client


@pytest.fixture
def anon(app):
    """A separate, never-signed-in client.

    The shared `client` fixture is the same object `auth_client` logs in, so a
    test that wants both an author and an anonymous visitor needs its own.
    """
    yield Client(app)


def _make_post(db, owner, *, slug, state=POST_PUBLISHED, title=None, **overrides):
    post = BlogPost(
        slug=slug,
        title=title or slug.replace("-", " ").title(),
        author=owner.display if owner else "Someone",
        user_id=owner.id if owner else None,
        category=overrides.pop("category", "Technology"),
        summary=overrides.pop("summary", ""),
        content=overrides.pop("content", BODY),
        reading_time=1,
        **overrides,
    )
    post.apply_state(state)
    db.add(post)
    db.commit()
    db.refresh(post)
    return post


def _write(client, **overrides):
    payload = {
        "title": "A brand new post",
        "category": "Technology",
        "content": BODY,
        "summary": "",
        "tags": "",
        "action": "draft",
    }
    payload.update(overrides)
    return client.post("/write", payload)


# ---------------------------------------------------------------------------
# Creating
# ---------------------------------------------------------------------------

def test_a_new_post_defaults_to_a_draft(auth_client, db, user):
    response = _write(auth_client)
    assert response.status_code == 303

    post = db.query(BlogPost).filter(BlogPost.user_id == user.id).first()
    assert post is not None
    assert post.state == POST_DRAFT
    assert post.published is False
    assert post.published_at is None


def test_publishing_on_create_sets_the_published_state(auth_client, db, user):
    assert _write(auth_client, action="publish").status_code == 303

    post = db.query(BlogPost).filter(BlogPost.user_id == user.id).first()
    assert post.state == POST_PUBLISHED
    assert post.published is True
    assert post.published_at is not None


def test_an_unknown_action_cannot_smuggle_a_publish(auth_client, db, user):
    assert _write(auth_client, action="publish-immediately-please").status_code == 303
    post = db.query(BlogPost).filter(BlogPost.user_id == user.id).first()
    # Anything unrecognised falls back to a draft rather than the riskier state.
    assert post.state == POST_DRAFT


def test_a_category_outside_the_whitelist_is_rejected(auth_client, db):
    response = _write(auth_client, category="<b>Made Up</b>")
    assert response.status_code == 400
    assert "Choose one of the listed categories." in response.text
    assert db.query(BlogPost).count() == 0


@pytest.mark.parametrize("overrides,expected", [
    ({"title": "abc"}, "Title must be at least"),
    ({"content": "too short"}, "Post content must be at least"),
])
def test_short_fields_are_rejected_with_a_message(auth_client, db, overrides, expected):
    response = _write(auth_client, **overrides)
    assert response.status_code == 400
    assert expected in response.text
    assert db.query(BlogPost).count() == 0


def test_two_posts_with_the_same_title_get_different_slugs(auth_client, db, user):
    _write(auth_client, title="Exactly the same title")
    _write(auth_client, title="Exactly the same title")

    slugs = [p.slug for p in db.query(BlogPost).filter(BlogPost.user_id == user.id).all()]
    assert len(slugs) == 2
    assert len(set(slugs)) == 2


def test_tags_are_attached_to_the_post(auth_client, db, user):
    assert _write(auth_client, tags="python, testing").status_code == 303
    post = db.query(BlogPost).filter(BlogPost.user_id == user.id).first()
    assert sorted(t.name for t in post.tags) == ["python", "testing"]


def test_the_public_write_form_offers_community_categories_only(auth_client):
    page = auth_client.get("/write")
    assert page.status_code == 200
    for category in BLOG_CATEGORIES:
        assert category in page.text
    # The research categories belong to the testing area. Offering them here
    # would let someone file a public post under lab terminology.
    for category in RESEARCH_CATEGORIES:
        assert category not in page.text


def test_a_research_category_is_refused_by_the_public_write_route(auth_client, db):
    response = _write(auth_client, category="Vulnerability Research")
    assert response.status_code == 400
    assert db.query(BlogPost).count() == 0


# ---------------------------------------------------------------------------
# Draft privacy
# ---------------------------------------------------------------------------

def test_the_author_can_preview_their_own_draft(auth_client, db, user):
    post = _make_post(db, user, slug="my-private-draft", state=POST_DRAFT)
    page = auth_client.get(f"/blog/{post.slug}")
    assert page.status_code == 200
    assert post.title in page.text


def test_a_draft_is_a_404_for_anonymous_visitors(client, db, user):
    post = _make_post(db, user, slug="hidden-draft", state=POST_DRAFT)
    assert client.get(f"/blog/{post.slug}").status_code == 404


def test_a_draft_is_a_404_for_another_signed_in_user(other_client, db, user):
    post = _make_post(db, user, slug="someone-elses-draft", state=POST_DRAFT)
    response = other_client.get(f"/blog/{post.slug}")
    # 404, not 403: a stranger learns nothing about whether the slug exists.
    assert response.status_code == 404


def test_a_draft_does_not_appear_in_public_listings(client, db, user):
    post = _make_post(db, user, slug="unlisted-draft", state=POST_DRAFT,
                      title="Unlisted Draft Title")
    for path in ("/blog", "/explore", "/", "/category/Technology"):
        assert post.title not in client.get(path).text, path


def test_an_archived_post_is_not_public_but_the_author_still_sees_it(
    auth_client, anon, db, user,
):
    post = _make_post(db, user, slug="old-archived-post", state=POST_ARCHIVED)
    assert anon.get(f"/blog/{post.slug}").status_code == 404
    assert auth_client.get(f"/blog/{post.slug}").status_code == 200


def test_my_posts_lists_drafts_and_only_your_own(auth_client, db, user, other_user):
    mine = _make_post(db, user, slug="mine-draft", state=POST_DRAFT, title="Mine Draft")
    theirs = _make_post(db, other_user, slug="theirs-draft", state=POST_DRAFT,
                        title="Theirs Draft")

    page = auth_client.get("/my/posts")
    assert page.status_code == 200
    assert mine.title in page.text
    assert theirs.title not in page.text


# ---------------------------------------------------------------------------
# Editing — ownership
# ---------------------------------------------------------------------------

def test_only_the_owner_can_open_the_edit_form(other_client, db, user):
    post = _make_post(db, user, slug="not-yours-to-edit")
    assert other_client.get(f"/blog/{post.slug}/edit").status_code == 403


def test_only_the_owner_can_submit_an_edit(other_client, db, user):
    post = _make_post(db, user, slug="not-yours-to-change")
    response = other_client.post(f"/blog/{post.slug}/edit", {
        "title": "Hijacked title", "category": "Technology",
        "content": BODY, "summary": "", "tags": "", "action": "keep",
    })
    assert response.status_code == 403

    db.expire_all()
    assert db.query(BlogPost).filter(BlogPost.id == post.id).first().title == post.title


def test_the_owner_can_edit_their_post(auth_client, db, user):
    post = _make_post(db, user, slug="mine-to-edit")
    response = auth_client.post(f"/blog/{post.slug}/edit", {
        "title": "A properly updated title", "category": "Programming",
        "content": BODY + " Plus a revision.", "summary": "New summary",
        "tags": "", "action": "keep",
    })
    assert response.status_code == 303

    db.expire_all()
    updated = db.query(BlogPost).filter(BlogPost.id == post.id).first()
    assert updated.title == "A properly updated title"
    assert updated.summary == "New summary"


def test_editing_an_unknown_slug_is_a_404(auth_client):
    assert auth_client.get("/blog/no-such-slug/edit").status_code == 404


# ---------------------------------------------------------------------------
# State changes
# ---------------------------------------------------------------------------

def test_publishing_a_draft_from_the_state_route(auth_client, db, user):
    post = _make_post(db, user, slug="draft-to-publish", state=POST_DRAFT)
    response = auth_client.post(f"/blog/{post.slug}/state", {"action": "publish"})
    assert response.status_code == 303
    assert response.headers["location"] == f"/blog/{post.slug}"

    db.expire_all()
    row = db.query(BlogPost).filter(BlogPost.id == post.id).first()
    assert row.state == POST_PUBLISHED
    assert row.published_at is not None


def test_unpublishing_sends_the_author_back_to_their_list(auth_client, db, user):
    post = _make_post(db, user, slug="published-to-unpublish")
    response = auth_client.post(f"/blog/{post.slug}/state", {"action": "draft"})
    assert response.status_code == 303
    assert response.headers["location"] == "/my/posts"

    db.expire_all()
    assert db.query(BlogPost).filter(BlogPost.id == post.id).first().state == POST_DRAFT


def test_archiving_a_post(auth_client, db, user):
    post = _make_post(db, user, slug="published-to-archive")
    assert auth_client.post(
        f"/blog/{post.slug}/state", {"action": "archive"},
    ).status_code == 303

    db.expire_all()
    assert db.query(BlogPost).filter(BlogPost.id == post.id).first().state == POST_ARCHIVED


def test_an_unknown_state_action_is_rejected(auth_client, db, user):
    post = _make_post(db, user, slug="state-action-guard", state=POST_DRAFT)
    assert auth_client.post(
        f"/blog/{post.slug}/state", {"action": "become-featured"},
    ).status_code == 400

    db.expire_all()
    assert db.query(BlogPost).filter(BlogPost.id == post.id).first().state == POST_DRAFT


def test_a_stranger_cannot_change_a_posts_state(other_client, db, user):
    post = _make_post(db, user, slug="state-not-yours", state=POST_DRAFT)
    assert other_client.post(
        f"/blog/{post.slug}/state", {"action": "publish"},
    ).status_code == 403

    db.expire_all()
    assert db.query(BlogPost).filter(BlogPost.id == post.id).first().state == POST_DRAFT


def test_republishing_keeps_the_original_publication_date(auth_client, db, user):
    post = _make_post(db, user, slug="date-stability")
    first_published = post.published_at

    auth_client.post(f"/blog/{post.slug}/state", {"action": "draft"})
    auth_client.post(f"/blog/{post.slug}/state", {"action": "publish"})

    db.expire_all()
    assert db.query(BlogPost).filter(
        BlogPost.id == post.id,
    ).first().published_at == first_published


# ---------------------------------------------------------------------------
# Deleting
# ---------------------------------------------------------------------------

def test_a_stranger_cannot_delete_your_post(other_client, db, user):
    post = _make_post(db, user, slug="delete-not-yours")
    assert other_client.post(f"/blog/{post.slug}/delete", {}).status_code == 403
    assert db.query(BlogPost).filter(BlogPost.id == post.id).count() == 1


def test_deleting_a_post_removes_the_rows_that_only_existed_for_it(
    auth_client, db, user, other_user,
):
    post = _make_post(db, user, slug="delete-with-children")
    comment = Comment(user_id=other_user.id, post_id=post.id, body="A comment.")
    db.add(comment)
    db.commit()
    db.refresh(comment)
    db.add_all([
        CommentLike(user_id=user.id, comment_id=comment.id, value=1),
        PostLike(user_id=other_user.id, post_id=post.id, value=1),
        Bookmark(user_id=other_user.id, post_id=post.id),
    ])
    db.commit()
    post_id, comment_id = post.id, comment.id

    response = auth_client.post(f"/blog/{post.slug}/delete", {})
    assert response.status_code == 303
    assert response.headers["location"] == "/my/posts"

    assert db.query(BlogPost).filter(BlogPost.id == post_id).count() == 0
    assert db.query(Comment).filter(Comment.id == comment_id).count() == 0
    assert db.query(CommentLike).filter(CommentLike.comment_id == comment_id).count() == 0
    assert db.query(PostLike).filter(PostLike.post_id == post_id).count() == 0
    assert db.query(Bookmark).filter(Bookmark.post_id == post_id).count() == 0


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------

def test_the_author_reading_their_own_post_does_not_inflate_views(auth_client, db, user):
    post = _make_post(db, user, slug="view-counting")
    auth_client.get(f"/blog/{post.slug}")

    db.expire_all()
    assert (db.query(BlogPost).filter(BlogPost.id == post.id).first().views or 0) == 0


def test_a_reader_increments_the_view_count(client, db, user):
    post = _make_post(db, user, slug="view-counting-stranger")
    client.get(f"/blog/{post.slug}")

    db.expire_all()
    assert db.query(BlogPost).filter(BlogPost.id == post.id).first().views == 1
