"""Admin operations that touch many tables at once — kept out of the route
handlers so the transaction boundaries and the delete-ordering live in one
audited place.

Why explicit deletes. The schema declares ``ON DELETE CASCADE`` on most
user- and post-owned rows, but the app runs on SQLite with foreign-key
enforcement left at its default (off), so those cascades never fire. Deleting a
user therefore has to remove every dependent row by hand, in an order that never
leaves an orphan. Getting this wrong doesn't just leak rows — a half-deleted
user can leave comments and posts pointing at a missing account. So the whole
thing runs inside a single transaction: it all lands, or none of it does.
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.models.activity import Activity
from app.models.blog_post import BlogPost
from app.models.moderation import ModerationAction, Report
from app.models.password_reset import PasswordResetToken
from app.models.social import (
    Bookmark, Comment, CommentLike, Follow, Notification, PostLike,
)
from app.models.training_example import TrainingExample
from app.models.user import User

logger = logging.getLogger("sentientai.admin")


# ---------------------------------------------------------------------------
# Post deletion — the single definition of "remove a post and everything that
# only exists because of it". Both the author-facing delete and admin removal
# go through here so the cascade can never drift between the two.
# ---------------------------------------------------------------------------

def delete_post_cascade(db: Session, post: BlogPost) -> None:
    """Remove a post and its dependent rows. Does NOT commit — the caller owns
    the transaction so this can be composed into a larger delete."""
    post_id = post.id

    comment_ids = [
        c.id for c in db.query(Comment.id).filter(Comment.post_id == post_id).all()
    ]
    if comment_ids:
        db.query(CommentLike).filter(
            CommentLike.comment_id.in_(comment_ids)
        ).delete(synchronize_session=False)
    db.query(Comment).filter(Comment.post_id == post_id).delete(synchronize_session=False)
    db.query(PostLike).filter(PostLike.post_id == post_id).delete(synchronize_session=False)
    db.query(Bookmark).filter(Bookmark.post_id == post_id).delete(synchronize_session=False)
    post.tags = []
    db.delete(post)


# ---------------------------------------------------------------------------
# User deletion
# ---------------------------------------------------------------------------

def _delete_user_owned_rows(db: Session, user_id: int) -> None:
    """Delete everything a single user owns. No commit — caller owns the txn.

    Order matters: comment-likes before comments, comments/likes/bookmarks
    before the posts they hang off, and the user's posts (with their own
    dependents) before the user row itself.
    """
    # 1. This user's interactions with *other people's* content.
    db.query(PostLike).filter(PostLike.user_id == user_id).delete(synchronize_session=False)
    db.query(CommentLike).filter(CommentLike.user_id == user_id).delete(synchronize_session=False)
    db.query(Bookmark).filter(Bookmark.user_id == user_id).delete(synchronize_session=False)
    db.query(Follow).filter(
        (Follow.follower_id == user_id) | (Follow.followed_id == user_id)
    ).delete(synchronize_session=False)
    db.query(Notification).filter(
        (Notification.user_id == user_id) | (Notification.actor_id == user_id)
    ).delete(synchronize_session=False)
    db.query(Activity).filter(Activity.user_id == user_id).delete(synchronize_session=False)

    # 2. Comments this user left on other people's posts (and any likes on them).
    own_comment_ids = [
        c.id for c in db.query(Comment.id).filter(Comment.user_id == user_id).all()
    ]
    if own_comment_ids:
        db.query(CommentLike).filter(
            CommentLike.comment_id.in_(own_comment_ids)
        ).delete(synchronize_session=False)
        db.query(Comment).filter(Comment.user_id == user_id).delete(synchronize_session=False)

    # 3. This user's own posts, each with its full dependent cascade.
    for post in db.query(BlogPost).filter(BlogPost.user_id == user_id).all():
        delete_post_cascade(db, post)

    # 4. Password-reset tokens (no ondelete rule, and they must not outlive the account).
    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user_id
    ).delete(synchronize_session=False)

    # 5. Rows the schema keeps but nulls out, since SQLite won't apply SET NULL.
    #    Reports filed by / resolved by the user, and moderation actions they took,
    #    are retained for the audit trail with the user reference cleared.
    db.query(Report).filter(Report.reporter_id == user_id).update(
        {Report.reporter_id: None}, synchronize_session=False)
    db.query(Report).filter(Report.resolved_by == user_id).update(
        {Report.resolved_by: None}, synchronize_session=False)
    db.query(ModerationAction).filter(ModerationAction.moderator_id == user_id).update(
        {ModerationAction.moderator_id: None}, synchronize_session=False)
    # Training examples this user reviewed keep the row (data provenance) but drop
    # the reviewer link, mirroring the SET NULL the DB would have done.
    db.query(TrainingExample).filter(TrainingExample.reviewed_by == user_id).update(
        {TrainingExample.reviewed_by: None}, synchronize_session=False)


def delete_user(db: Session, user: User) -> None:
    """Permanently delete one account and everything it owns, in one transaction.

    Refuses to delete an admin: demoting/removing an administrator is a
    deliberate operator action (manage.py), never a click in the web UI, so an
    admin account can't be destroyed — including the last one — by accident.
    """
    if user.role == "admin":
        raise ValueError("Administrator accounts cannot be deleted from the admin panel.")
    user_id = user.id
    try:
        _delete_user_owned_rows(db, user_id)
        db.delete(user)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Failed to delete user %s; rolled back.", user_id)
        raise


# ---------------------------------------------------------------------------
# Remove all normal users — the "reset to a single admin" operation
# ---------------------------------------------------------------------------

def remove_all_normal_users(db: Session) -> int:
    """Delete every non-admin account and its data, preserving all admins and
    system configuration. Returns the number of accounts removed.

    Runs as one transaction: a failure part-way leaves the database exactly as
    it was. Admin-owned content is untouched.
    """
    normal_users = db.query(User).filter(User.role != "admin").all()
    if not normal_users:
        return 0
    try:
        for user in normal_users:
            _delete_user_owned_rows(db, user.id)
            db.delete(user)
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("remove_all_normal_users failed; rolled back.")
        raise
    return len(normal_users)
