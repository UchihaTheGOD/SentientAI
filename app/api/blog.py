"""Blog routes — listing, individual posts, and user-authored content."""
import re
from datetime import datetime, timezone
from fastapi import APIRouter, Request, Depends, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.blog_post import BlogPost, BLOG_CATEGORIES, ALL_CATEGORIES
from app.models.user import User
from app.models.social import PostLike, Bookmark, Comment
from app.services.auth_service import get_current_user, get_current_user_optional
from app.services.activity_service import log_activity

router = APIRouter(tags=["blog"])
templates = Jinja2Templates(directory="app/templates")


def _slugify(text: str) -> str:
    """Generate a URL-safe slug from a title."""
    slug = text.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug[:190]  # keep under max slug length


def _estimate_reading_time(content: str) -> int:
    """Estimate reading time in minutes (avg 200 wpm for technical content)."""
    words = len(content.split())
    return max(1, round(words / 200))


# ---- Public routes ----

@router.get("/blog", response_class=HTMLResponse)
def blog_index(
    request: Request,
    category: str = "",
    user=Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    query = db.query(BlogPost).filter(BlogPost.published == True)
    if category and category in BLOG_CATEGORIES:
        query = query.filter(BlogPost.category == category)
    posts = query.order_by(BlogPost.created_at.desc()).all()

    return templates.TemplateResponse("blog/index.html", {
        "request": request,
        "current_user": user,
        "posts": posts,
        "categories": BLOG_CATEGORIES,
        "active_category": category if category in BLOG_CATEGORIES else None,
    })


@router.get("/blog/{slug}", response_class=HTMLResponse)
def blog_post(
    slug: str,
    request: Request,
    user=Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    post = db.query(BlogPost).filter(
        BlogPost.slug == slug,
        BlogPost.published == True,
    ).first()
    if not post:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

    # Increment view counter
    post.views = (post.views or 0) + 1
    db.commit()

    # Resolve author user if linked
    author_user = None
    if post.user_id:
        author_user = db.query(User).filter(User.id == post.user_id).first()

    # Like/dislike counts
    likes = db.query(func.count(PostLike.id)).filter(
        PostLike.post_id == post.id, PostLike.value == 1
    ).scalar() or 0
    dislikes = db.query(func.count(PostLike.id)).filter(
        PostLike.post_id == post.id, PostLike.value == -1
    ).scalar() or 0

    # Current user's vote and bookmark
    user_vote = None
    user_bookmarked = False
    if user:
        vote_row = db.query(PostLike).filter(
            PostLike.user_id == user.id, PostLike.post_id == post.id
        ).first()
        user_vote = vote_row.value if vote_row else None
        user_bookmarked = db.query(Bookmark).filter(
            Bookmark.user_id == user.id, Bookmark.post_id == post.id
        ).first() is not None

    # Comments (top-level + replies)
    top_comments = (
        db.query(Comment)
        .filter(Comment.post_id == post.id, Comment.parent_id == None)
        .order_by(Comment.created_at.asc())
        .all()
    )
    # Build reply map
    reply_map = {}
    all_replies = (
        db.query(Comment)
        .filter(Comment.post_id == post.id, Comment.parent_id != None)
        .order_by(Comment.created_at.asc())
        .all()
    )
    for reply in all_replies:
        reply_map.setdefault(reply.parent_id, []).append(reply)

    # Comment author names
    comment_user_ids = list({c.user_id for c in top_comments + all_replies})
    comment_users = {}
    if comment_user_ids:
        for u in db.query(User).filter(User.id.in_(comment_user_ids)).all():
            comment_users[u.id] = u

    return templates.TemplateResponse("blog/post.html", {
        "request": request,
        "current_user": user,
        "post": post,
        "author_user": author_user,
        "likes": likes,
        "dislikes": dislikes,
        "user_vote": user_vote,
        "user_bookmarked": user_bookmarked,
        "top_comments": top_comments,
        "reply_map": reply_map,
        "comment_users": comment_users,
    })


# ---- Authenticated routes ----

@router.get("/write", response_class=HTMLResponse)
def write_post_form(
    request: Request,
    user: User = Depends(get_current_user),
):
    return templates.TemplateResponse("blog/write.html", {
        "request": request,
        "current_user": user,
        "categories": ALL_CATEGORIES,
        "post": None,  # new post mode
        "errors": [],
    })


@router.post("/write", response_class=HTMLResponse)
def write_post_submit(
    request: Request,
    title: str = Form(...),
    category: str = Form(...),
    content: str = Form(...),
    summary: str = Form(""),
    published: bool = Form(False),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    errors = []

    # Validation
    if len(title.strip()) < 5:
        errors.append("Title must be at least 5 characters.")
    if category not in ALL_CATEGORIES:
        errors.append("Invalid category.")
    if len(content.strip()) < 20:
        errors.append("Content must be at least 20 characters.")

    if errors:
        return templates.TemplateResponse("blog/write.html", {
            "request": request,
            "current_user": user,
            "categories": ALL_CATEGORIES,
            "post": {"title": title, "category": category, "content": content, "summary": summary},
            "errors": errors,
        })

    # Generate unique slug
    base_slug = _slugify(title)
    slug = base_slug
    counter = 1
    while db.query(BlogPost).filter(BlogPost.slug == slug).first():
        slug = f"{base_slug}-{counter}"
        counter += 1

    post = BlogPost(
        title=title.strip(),
        slug=slug,
        author=user.display,
        user_id=user.id,
        category=category,
        summary=summary.strip(),
        content=content.strip(),
        reading_time=_estimate_reading_time(content),
        published=published,
    )
    db.add(post)
    db.commit()
    db.refresh(post)

    # Log activity
    activity_type = "blog_post_published" if published else "blog_post_created"
    log_activity(
        db, user.id, activity_type,
        f'{"Published" if published else "Created draft"}: {title.strip()}',
        target_type="blog_post", target_id=str(post.id),
    )

    if published:
        return RedirectResponse(url=f"/blog/{post.slug}", status_code=303)
    return RedirectResponse(url=f"/blog/{post.slug}/edit", status_code=303)


@router.get("/blog/{slug}/edit", response_class=HTMLResponse)
def edit_post_form(
    slug: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    post = db.query(BlogPost).filter(BlogPost.slug == slug).first()
    if not post:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

    # IDOR protection: only the author (or admin) can edit
    if post.user_id != user.id and not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot edit another user's post")

    return templates.TemplateResponse("blog/write.html", {
        "request": request,
        "current_user": user,
        "categories": BLOG_CATEGORIES,
        "post": post,
        "errors": [],
    })


@router.post("/blog/{slug}/edit", response_class=HTMLResponse)
def edit_post_submit(
    slug: str,
    request: Request,
    title: str = Form(...),
    category: str = Form(...),
    content: str = Form(...),
    summary: str = Form(""),
    published: bool = Form(False),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    post = db.query(BlogPost).filter(BlogPost.slug == slug).first()
    if not post:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

    if post.user_id != user.id and not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot edit another user's post")

    errors = []
    if len(title.strip()) < 5:
        errors.append("Title must be at least 5 characters.")
    if category not in BLOG_CATEGORIES:
        errors.append("Invalid category.")
    if len(content.strip()) < 20:
        errors.append("Content must be at least 20 characters.")

    if errors:
        return templates.TemplateResponse("blog/write.html", {
            "request": request,
            "current_user": user,
            "categories": BLOG_CATEGORIES,
            "post": post,
            "errors": errors,
        })

    was_draft = not post.published

    post.title = title.strip()
    post.category = category
    post.content = content.strip()
    post.summary = summary.strip()
    post.reading_time = _estimate_reading_time(content)
    post.published = published
    post.updated_at = datetime.now(timezone.utc)
    db.commit()

    # Log activity
    if was_draft and published:
        log_activity(db, user.id, "blog_post_published", f"Published: {title.strip()}",
                     target_type="blog_post", target_id=str(post.id))
    else:
        log_activity(db, user.id, "blog_post_updated", f"Updated: {title.strip()}",
                     target_type="blog_post", target_id=str(post.id))

    return RedirectResponse(url=f"/blog/{post.slug}", status_code=303)

