"""Social interaction routes — likes, comments, bookmarks, follows, notifications."""
from datetime import datetime, timezone
from fastapi import APIRouter, Request, Depends, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.user import User
from app.models.blog_post import BlogPost
from app.models.social import PostLike, Comment, CommentLike, Bookmark, Follow, Notification
from app.services.auth_service import get_current_user, get_current_user_optional
from app.services.activity_service import log_activity

router = APIRouter(tags=["social"])
templates = Jinja2Templates(directory="app/templates")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_notification(db: Session, user_id: int, actor_id: int, notif_type: str,
                          message: str, target_url: str = None):
    """Create a notification for a user, skipping self-notifications."""
    if user_id == actor_id:
        return
    notif = Notification(
        user_id=user_id,
        actor_id=actor_id,
        notif_type=notif_type,
        message=message,
        target_url=target_url,
    )
    db.add(notif)


def _get_post_stats(db: Session, post_id: int) -> dict:
    """Return like/dislike/comment counts for a post."""
    likes = db.query(func.count(PostLike.id)).filter(
        PostLike.post_id == post_id, PostLike.value == 1
    ).scalar() or 0
    dislikes = db.query(func.count(PostLike.id)).filter(
        PostLike.post_id == post_id, PostLike.value == -1
    ).scalar() or 0
    comments = db.query(func.count(Comment.id)).filter(
        Comment.post_id == post_id, Comment.is_deleted == False
    ).scalar() or 0
    return {"likes": likes, "dislikes": dislikes, "comments": comments}


# ---------------------------------------------------------------------------
# Like / Dislike
# ---------------------------------------------------------------------------

@router.post("/blog/{slug}/like")
def like_post(
    slug: str,
    value: int = Form(1),  # +1 like, -1 dislike
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    request: Request = None,
):
    """Toggle like/dislike on a post. Re-voting same value removes it."""
    post = db.query(BlogPost).filter(BlogPost.slug == slug, BlogPost.published == True).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    if value not in (1, -1):
        raise HTTPException(status_code=400, detail="Invalid vote value")

    existing = db.query(PostLike).filter(
        PostLike.user_id == user.id, PostLike.post_id == post.id
    ).first()

    if existing:
        if existing.value == value:
            # Same vote → remove (toggle off)
            db.delete(existing)
            db.commit()
        else:
            # Change vote
            existing.value = value
            db.commit()
            if value == 1 and post.user_id:
                _create_notification(db, post.user_id, user.id, "like",
                                     f"{user.display} liked your post: {post.title}",
                                     f"/blog/{post.slug}")
                db.commit()
    else:
        vote = PostLike(user_id=user.id, post_id=post.id, value=value)
        db.add(vote)
        db.commit()
        if value == 1 and post.user_id:
            _create_notification(db, post.user_id, user.id, "like",
                                 f"{user.display} liked your post: {post.title}",
                                 f"/blog/{post.slug}")
            db.commit()

    stats = _get_post_stats(db, post.id)
    # Return JSON for HTMX/JS, or redirect for plain form
    accept = request.headers.get("accept", "") if request else ""
    if "application/json" in accept:
        return JSONResponse(stats)
    return RedirectResponse(url=f"/blog/{slug}", status_code=303)


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------

@router.post("/blog/{slug}/comment")
def post_comment(
    slug: str,
    body: str = Form(...),
    parent_id: int = Form(None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    post = db.query(BlogPost).filter(BlogPost.slug == slug, BlogPost.published == True).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    body = body.strip()
    if len(body) < 2:
        return RedirectResponse(url=f"/blog/{slug}#comments", status_code=303)
    if len(body) > 2000:
        body = body[:2000]

    # Validate parent_id if provided
    if parent_id:
        parent = db.query(Comment).filter(
            Comment.id == parent_id, Comment.post_id == post.id
        ).first()
        if not parent:
            parent_id = None

    comment = Comment(
        user_id=user.id,
        post_id=post.id,
        parent_id=parent_id,
        body=body,
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)

    # Notify post author
    if post.user_id:
        _create_notification(db, post.user_id, user.id, "comment",
                             f"{user.display} commented on your post: {post.title}",
                             f"/blog/{post.slug}#comment-{comment.id}")
        db.commit()

    # Notify parent comment author on reply
    if parent_id:
        parent_comment = db.query(Comment).filter(Comment.id == parent_id).first()
        if parent_comment and parent_comment.user_id != post.user_id:
            _create_notification(db, parent_comment.user_id, user.id, "reply",
                                 f"{user.display} replied to your comment",
                                 f"/blog/{post.slug}#comment-{comment.id}")
            db.commit()

    log_activity(db, user.id, "comment_posted", f"Commented on: {post.title}",
                 target_type="blog_post", target_id=str(post.id))

    return RedirectResponse(url=f"/blog/{slug}#comment-{comment.id}", status_code=303)


@router.post("/blog/{slug}/comment/{comment_id}/delete")
def delete_comment(
    slug: str,
    comment_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    comment = db.query(Comment).filter(Comment.id == comment_id).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    if comment.user_id != user.id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Not your comment")

    # Soft delete — keep threading intact
    comment.is_deleted = True
    comment.body = "[deleted]"
    db.commit()

    return RedirectResponse(url=f"/blog/{slug}#comments", status_code=303)


@router.post("/blog/{slug}/comment/{comment_id}/edit")
def edit_comment(
    slug: str,
    comment_id: int,
    body: str = Form(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    comment = db.query(Comment).filter(Comment.id == comment_id).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    if comment.user_id != user.id:
        raise HTTPException(status_code=403, detail="Not your comment")

    body = body.strip()
    if len(body) < 2:
        return RedirectResponse(url=f"/blog/{slug}#comment-{comment_id}", status_code=303)

    comment.body = body[:2000]
    comment.updated_at = datetime.now(timezone.utc)
    db.commit()

    return RedirectResponse(url=f"/blog/{slug}#comment-{comment_id}", status_code=303)


@router.post("/comment/{comment_id}/like")
def like_comment(
    comment_id: int,
    value: int = Form(1),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    comment = db.query(Comment).filter(Comment.id == comment_id, Comment.is_deleted == False).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")

    existing = db.query(CommentLike).filter(
        CommentLike.user_id == user.id, CommentLike.comment_id == comment_id
    ).first()

    if existing:
        if existing.value == value:
            db.delete(existing)
        else:
            existing.value = value
    else:
        db.add(CommentLike(user_id=user.id, comment_id=comment_id, value=value))

    db.commit()
    # Get post slug to redirect back
    post = db.query(BlogPost).filter(BlogPost.id == comment.post_id).first()
    slug = post.slug if post else ""
    return RedirectResponse(url=f"/blog/{slug}#comment-{comment_id}", status_code=303)


# ---------------------------------------------------------------------------
# Bookmarks
# ---------------------------------------------------------------------------

@router.post("/blog/{slug}/bookmark")
def toggle_bookmark(
    slug: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    post = db.query(BlogPost).filter(BlogPost.slug == slug, BlogPost.published == True).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")

    existing = db.query(Bookmark).filter(
        Bookmark.user_id == user.id, Bookmark.post_id == post.id
    ).first()

    if existing:
        db.delete(existing)
        db.commit()
    else:
        db.add(Bookmark(user_id=user.id, post_id=post.id))
        db.commit()

    return RedirectResponse(url=f"/blog/{slug}", status_code=303)


@router.get("/bookmarks", response_class=HTMLResponse)
def bookmarks_page(
    request: Request,
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
    posts = db.query(BlogPost).filter(BlogPost.id.in_(post_ids)).all() if post_ids else []
    posts_map = {p.id: p for p in posts}
    bookmarked_posts = [posts_map[b.post_id] for b in bookmarks if b.post_id in posts_map]

    return templates.TemplateResponse("bookmarks.html", {
        "request": request,
        "current_user": user,
        "bookmarked_posts": bookmarked_posts,
    })


# ---------------------------------------------------------------------------
# Follows
# ---------------------------------------------------------------------------

@router.post("/users/{username}/follow")
def toggle_follow(
    username: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == user.id:
        raise HTTPException(status_code=400, detail="Cannot follow yourself")

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
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    notifs = (
        db.query(Notification)
        .filter(Notification.user_id == user.id)
        .order_by(Notification.created_at.desc())
        .limit(50)
        .all()
    )

    # Mark all as read
    db.query(Notification).filter(
        Notification.user_id == user.id, Notification.is_read == False
    ).update({"is_read": True})
    db.commit()

    return templates.TemplateResponse("notifications.html", {
        "request": request,
        "current_user": user,
        "notifications": notifs,
    })
