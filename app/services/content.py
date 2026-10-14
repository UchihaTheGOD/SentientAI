"""Shared content queries and visibility rules.

One definition of "a visitor may see this" so every feed, search result, sitemap
and count agrees. `is_public` on the model is the display-time check; these are
the query-time equivalents.
"""
from __future__ import annotations

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.blog_post import POST_PUBLISHED, BlogPost
from app.models.social import Comment, PostLike
from app.models.user import User


def public_posts_query(db: Session):
    """Posts an anonymous visitor is allowed to see."""
    return db.query(BlogPost).filter(
        BlogPost.status == POST_PUBLISHED,
        BlogPost.is_hidden == False,  # noqa: E712
    )


def visible_comments_query(db: Session, post_id: int):
    """Comments a visitor is allowed to see (author-deleted rows are kept so
    threading survives, but moderator-hidden rows are excluded outright)."""
    return db.query(Comment).filter(
        Comment.post_id == post_id,
        Comment.is_hidden == False,  # noqa: E712
    )


def comment_counts(db: Session, post_ids: list[int]) -> dict[int, int]:
    """{post_id: visible comment count} — replaces the hardcoded zeros."""
    if not post_ids:
        return {}
    rows = (
        db.query(Comment.post_id, func.count(Comment.id))
        .filter(
            Comment.post_id.in_(post_ids),
            Comment.is_deleted == False,  # noqa: E712
            Comment.is_hidden == False,  # noqa: E712
        )
        .group_by(Comment.post_id)
        .all()
    )
    return {post_id: count for post_id, count in rows}


def like_counts(db: Session, post_ids: list[int]) -> dict[int, int]:
    if not post_ids:
        return {}
    rows = (
        db.query(PostLike.post_id, func.count(PostLike.id))
        .filter(PostLike.post_id.in_(post_ids), PostLike.value == 1)
        .group_by(PostLike.post_id)
        .all()
    )
    return {post_id: count for post_id, count in rows}


def authors_for(db: Session, posts) -> dict[int, User]:
    """{user_id: User} for a batch of posts, so cards can link to real profiles."""
    ids = {p.user_id for p in posts if getattr(p, "user_id", None)}
    if not ids:
        return {}
    return {u.id: u for u in db.query(User).filter(User.id.in_(ids)).all()}


def post_card_context(db: Session, posts) -> dict:
    """Everything a list of post cards needs, in three queries."""
    ids = [p.id for p in posts]
    return {
        "comment_counts": comment_counts(db, ids),
        "like_counts": like_counts(db, ids),
        "authors": authors_for(db, posts),
    }


def can_view_post(post: BlogPost, user: User | None) -> bool:
    """Server-side visibility check.

    Authors may preview their own drafts and archived posts; admins may view
    anything (including moderator-hidden posts) so the queue is usable. Everyone
    else only sees published, unhidden posts.
    """
    if post is None:
        return False
    if post.is_public:
        return True
    if user is None:
        return False
    if user.is_admin:
        return True
    return post.user_id is not None and post.user_id == user.id


def can_edit_post(post: BlogPost, user: User | None) -> bool:
    if post is None or user is None:
        return False
    return user.is_admin or (post.user_id is not None and post.user_id == user.id)
