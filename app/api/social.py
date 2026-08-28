"""Social interaction routes — likes, comments, bookmarks, follows, notifications.

Everything here is a state change made by a signed-in person, so every route
carries the same three things: `get_current_user` (a real dependency, not an
"is there a cookie?" check), a rate limit, and an ownership check before any row
is touched. Comment bodies are stored as the text the author typed and rendered
through the `content` filter (app/services/sanitize.py) — never `| safe`.

Reactions and comments only apply to posts a visitor could see in the first
place, so a hidden or draft post cannot be liked, bookmarked or commented on.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.blog_post import BlogPost
from app.models.social import Bookmark, Comment, CommentLike, Follow, Notification, PostLike
from app.models.user import User
from app.services import audit
from app.services.activity_service import log_activity
from app.services.auth_service import get_current_user
from app.services.content import public_posts_query
from app.services.pagination import clamp_page, paginate_list
from app.services.ratelimit import limit_comment, limit_reaction
from app.services.sanitize import clean_text
from app.template_env import templates

router = APIRouter(tags=["social"])

MAX_COMMENT = 2000
MIN_COMMENT = 2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _visible_post(db: Session, slug: str) -> BlogPost:
    """The post, or 404. Uses the one shared definition of public visibility so
    a draft or moderator-hidden post cannot be interacted with."""
    post = public_posts_query(db).filter(BlogPost.slug == slug).first()
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")
    return post


def _create_notification(db: Session, user_id: int, actor_id: int, notif_type: str,
                         message: str, target_url: str | None = None):
    """Create a notification for a user, skipping self-notifications."""
    if not user_id or user_id == actor_id:
        return
    db.add(Notification(
        user_id=user_id,
        actor_id=actor_id,
        notif_type=notif_type,
        message=message[:500],
        target_url=target_url,
    ))


def _get_post_stats(db: Session, post_id: int) -> dict:
    """Like/dislike/comment counts for a post, matching what the page shows."""
    likes = db.query(func.count(PostLike.id)).filter(
        PostLike.post_id == post_id, PostLike.value == 1
    ).scalar() or 0
    dislikes = db.query(func.count(PostLike.id)).filter(
        PostLike.post_id == post_id, PostLike.value == -1
    ).scalar() or 0
    comments = db.query(func.count(Comment.id)).filter(
        Comment.post_id == post_id,
        Comment.is_deleted == False,  # noqa: E712
        Comment.is_hidden == False,  # noqa: E712
    ).scalar() or 0
    return {"likes": likes, "dislikes": dislikes, "comments": comments}


# ---------------------------------------------------------------------------
# Like / dislike
# ---------------------------------------------------------------------------

@router.post("/blog/{slug}/like", dependencies=[Depends(limit_reaction)])
def like_post(
    slug: str,
    request: Request,
    value: int = Form(1),  # +1 like, -1 dislike
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Toggle like/dislike on a post. Re-voting the same way removes the vote."""
    post = _visible_post(db, slug)
    if value not in (1, -1):
        raise HTTPException(status_code=400, detail="Invalid vote value")

    existing = db.query(PostLike).filter(
        PostLike.user_id == user.id, PostLike.post_id == post.id
    ).first()

    notify = False
    if existing is None:
        db.add(PostLike(user_id=user.id, post_id=post.id, value=value))
        notify = value == 1
    elif existing.value == value:
        db.delete(existing)  # toggle off
    else:
        existing.value = value
        notify = value == 1
    db.commit()

    if notify and post.user_id:
        _create_notification(db, post.user_id, user.id, "like",
                             f"{user.display} liked your post: {post.title}",
                             f"/blog/{post.slug}")
        db.commit()

    stats = _get_post_stats(db, post.id)
    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse(stats)
    return RedirectResponse(url=f"/blog/{slug}", status_code=303)


@router.post("/comment/{comment_id}/like", dependencies=[Depends(limit_reaction)])
def like_comment(
    comment_id: int,
    value: int = Form(1),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    comment = (
        db.query(Comment)
        .filter(
            Comment.id == comment_id,
            Comment.is_deleted == False,  # noqa: E712
            Comment.is_hidden == False,  # noqa: E712
        )
        .first()
    )
    if comment is None:
        raise HTTPException(status_code=404, detail="Comment not found")
    if value not in (1, -1):
        raise HTTPException(status_code=400, detail="Invalid vote value")

    existing = db.query(CommentLike).filter(
        CommentLike.user_id == user.id, CommentLike.comment_id == comment_id
    ).first()
    if existing is None:
        db.add(CommentLike(user_id=user.id, comment_id=comment_id, value=value))
    elif existing.value == value:
        db.delete(existing)
    else:
        existing.value = value
    db.commit()

    post = db.query(BlogPost).filter(BlogPost.id == comment.post_id).first()
    slug = post.slug if post else ""
    return RedirectResponse(url=f"/blog/{slug}#comment-{comment_id}", status_code=303)


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------

@router.post("/blog/{slug}/comment", dependencies=[Depends(limit_comment)])
def post_comment(
    slug: str,
    request: Request,
    body: str = Form(...),
    parent_id: int = Form(None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    post = _visible_post(db, slug)

    # Stored as plain text; control characters stripped and length capped.
    # Rendering is the sanitizer's job, not this route's.
    body = clean_text(body, MAX_COMMENT)
    if len(body) < MIN_COMMENT:
        return RedirectResponse(url=f"/blog/{slug}#comments", status_code=303)

    # Only one level of threading: a reply to a reply attaches to its parent.
    if parent_id:
        parent = (
            db.query(Comment)
            .filter(Comment.id == parent_id, Comment.post_id == post.id)
            .first()
        )
        if parent is None:
            parent_id = None
        elif parent.parent_id:
            parent_id = parent.parent_id

    comment = Comment(user_id=user.id, post_id=post.id, parent_id=parent_id, body=body)
    db.add(comment)
    db.commit()
    db.refresh(comment)

    if post.user_id:
        _create_notification(db, post.user_id, user.id, "comment",
                             f"{user.display} commented on your post: {post.title}",
                             f"/blog/{post.slug}#comment-{comment.id}")
        db.commit()

    if parent_id:
        parent_comment = db.query(Comment).filter(Comment.id == parent_id).first()
        if parent_comment and parent_comment.user_id != post.user_id:
            _create_notification(db, parent_comment.user_id, user.id, "reply",
                                 f"{user.display} replied to your comment",
                                 f"/blog/{post.slug}#comment-{comment.id}")
            db.commit()

    log_activity(db, user.id, "comment_posted", f"Commented on: {post.title}",
                 target_type="blog_post", target_id=str(post.id))
    audit.record(db, "comment.created", user=user, target_type="comment",
                 target_id=comment.id, request=request)
    audit.bump_metric(db, "comments")

    return RedirectResponse(url=f"/blog/{slug}#comment-{comment.id}", status_code=303)


@router.post("/blog/{slug}/comment/{comment_id}/delete")
def delete_comment(
    slug: str,
    comment_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    comment = db.query(Comment).filter(Comment.id == comment_id).first()
    if comment is None:
        raise HTTPException(status_code=404, detail="Comment not found")
    # Ownership check, not a UI check: the Delete button is only rendered for
    # the author, but the route is what actually enforces it.
    if comment.user_id != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="You can only delete your own comments.")

    # Soft delete so threading survives. The body is kept in the row (the
    # template shows a placeholder instead) so a later report about this comment
    # can still be reviewed.
    comment.is_deleted = True
    comment.updated_at = datetime.now(timezone.utc)
    db.commit()
    audit.record(db, "comment.deleted", user=user, target_type="comment",
                 target_id=comment_id,
                 detail="own comment" if comment.user_id == user.id else "admin removal",
                 request=request)

    return RedirectResponse(url=f"/blog/{slug}#comments", status_code=303)


@router.post("/blog/{slug}/comment/{comment_id}/edit",
             dependencies=[Depends(limit_comment)])
def edit_comment(
    slug: str,
    comment_id: int,
    body: str = Form(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    comment = db.query(Comment).filter(Comment.id == comment_id).first()
    if comment is None:
        raise HTTPException(status_code=404, detail="Comment not found")
    # Editing is the author's alone — an admin may hide a comment, but never
    # rewrite what someone said.
    if comment.user_id != user.id:
        raise HTTPException(status_code=403, detail="You can only edit your own comments.")
    if comment.is_deleted or comment.is_hidden:
        raise HTTPException(status_code=403, detail="This comment can no longer be edited.")

    cleaned = clean_text(body, MAX_COMMENT)
    if len(cleaned) < MIN_COMMENT:
        return RedirectResponse(url=f"/blog/{slug}#comment-{comment_id}", status_code=303)

    comment.body = cleaned
    comment.updated_at = datetime.now(timezone.utc)
    db.commit()
    return RedirectResponse(url=f"/blog/{slug}#comment-{comment_id}", status_code=303)


# ---------------------------------------------------------------------------
# Bookmarks
# ---------------------------------------------------------------------------

@router.post("/blog/{slug}/bookmark", dependencies=[Depends(limit_reaction)])
def toggle_bookmark(
    slug: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    post = _visible_post(db, slug)
    existing = db.query(Bookmark).filter(
        Bookmark.user_id == user.id, Bookmark.post_id == post.id
    ).first()
    if existing:
        db.delete(existing)
    else:
        db.add(Bookmark(user_id=user.id, post_id=post.id))
    db.commit()
    return RedirectResponse(url=f"/blog/{slug}", status_code=303)


@router.get("/bookmarks", response_class=HTMLResponse)
def bookmarks_page(
    request: Request,
    page: int = 1,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    bookmarks = (
        db.query(Bookmark)
        .filter(Bookmark.user_id == user.id)
        .order_by(Bookmark.created_at.desc())
        .all()
    )
    post_ids = [b.post_id for b in bookmarks]
    # A bookmarked post that has since been hidden or unpublished drops out of
    # the list rather than 404ing when clicked.
    posts = (
        {p.id: p for p in public_posts_query(db).filter(BlogPost.id.in_(post_ids)).all()}
        if post_ids else {}
    )
    ordered = [posts[b.post_id] for b in bookmarks if b.post_id in posts]
    paged = paginate_list(ordered, clamp_page(page), 12)

    return templates.TemplateResponse("bookmarks.html", {
        "request": request,
        "current_user": user,
        "bookmarked_posts": paged.items,
        "page": paged,
        "params": {},
    })


# ---------------------------------------------------------------------------
# Follows
# ---------------------------------------------------------------------------

@router.post("/users/{username}/follow", dependencies=[Depends(limit_reaction)])
def toggle_follow(
    username: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    target = db.query(User).filter(User.username == username).first()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == user.id:
        raise HTTPException(status_code=400, detail="You cannot follow yourself.")

    existing = db.query(Follow).filter(
        Follow.follower_id == user.id, Follow.followed_id == target.id
    ).first()
    if existing:
        db.delete(existing)
        db.commit()
    else:
        db.add(Follow(follower_id=user.id, followed_id=target.id))
        db.commit()
        _create_notification(db, target.id, user.id, "follow",
                             f"{user.display} started following you",
                             f"/u/{user.username}")
        db.commit()
        log_activity(db, user.id, "followed_user", f"Followed {target.display}",
                     target_type="user", target_id=str(target.id), is_public=False)

    return RedirectResponse(url=f"/u/{username}", status_code=303)


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

@router.get("/notifications", response_class=HTMLResponse)
def notifications_page(
    request: Request,
    page: int = 1,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Opening the page no longer marks everything read — that made it
    impossible to come back to something you meant to deal with later."""
    query = (
        db.query(Notification)
        .filter(Notification.user_id == user.id)
        .order_by(Notification.created_at.desc())
    )
    from app.services.pagination import paginate

    paged = paginate(query, clamp_page(page), 25)
    unread = (
        db.query(func.count(Notification.id))
        .filter(Notification.user_id == user.id, Notification.is_read == False)  # noqa: E712
        .scalar()
    ) or 0

    return templates.TemplateResponse("notifications.html", {
        "request": request,
        "current_user": user,
        "notifications": paged.items,
        "page": paged,
        "unread": unread,
        "params": {},
    })


@router.post("/notifications/read-all")
def mark_all_notifications_read(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    db.query(Notification).filter(
        Notification.user_id == user.id,
        Notification.is_read == False,  # noqa: E712
    ).update({"is_read": True})
    db.commit()
    return RedirectResponse(url="/notifications", status_code=303)


@router.post("/notifications/{notification_id}/read")
def mark_notification_read(
    notification_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    notif = (
        db.query(Notification)
        .filter(Notification.id == notification_id, Notification.user_id == user.id)
        .first()
    )
    # Scoped to the owner, so guessing another user's notification id gets a 404
    # rather than marking their notification read.
    if notif is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    notif.is_read = True
    db.commit()
    return RedirectResponse(url=notif.target_url or "/notifications", status_code=303)
