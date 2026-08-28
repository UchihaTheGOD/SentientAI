"""Public-facing routes — homepage, about, contact, profile."""
from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.database import get_db
from app.models.user import User
from app.models.blog_post import POST_PUBLISHED, BlogPost, BLOG_CATEGORIES
from app.models.social import PostLike, Follow
from app.services.auth_service import get_current_user, get_current_user_optional
from app.services.content import public_posts_query
from app.template_env import templates

router = APIRouter(tags=["public"])


@router.get("/", response_class=HTMLResponse)
def index(
    request: Request,
    user=Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    # `public_posts_query` is the single definition of "a visitor may see
    # this": published and not moderator-hidden.
    base_q = public_posts_query(db)

    # Featured: most-viewed
    featured_posts = base_q.order_by(desc(BlogPost.views)).limit(3).all()

    # Latest
    latest_posts = base_q.order_by(desc(BlogPost.created_at)).limit(6).all()

    # Trending: highest like count in last N (use views as simple proxy for now)
    trending_posts = base_q.order_by(desc(BlogPost.views)).offset(3).limit(6).all()

    # Popular authors (users with most published posts)
    popular_authors = (
        db.query(User, func.count(BlogPost.id).label("post_count"))
        .join(BlogPost, BlogPost.user_id == User.id)
        .filter(
            BlogPost.status == POST_PUBLISHED,
            BlogPost.is_hidden == False,  # noqa: E712
            User.is_suspended == False,  # noqa: E712
        )
        .group_by(User.id)
        .order_by(func.count(BlogPost.id).desc())
        .limit(5)
        .all()
    )

    # Stats for social proof
    total_posts = base_q.count()
    total_users = db.query(func.count(User.id)).filter(User.is_active == True).scalar() or 0

    return templates.TemplateResponse("index.html", {
        "request": request,
        "current_user": user,
        "featured_posts": featured_posts,
        "latest_posts": latest_posts,
        "trending_posts": trending_posts,
        "popular_authors": popular_authors,
        "categories": BLOG_CATEGORIES,
        "total_posts": total_posts,
        "total_users": total_users,
    })


@router.get("/about", response_class=HTMLResponse)
def about(request: Request, user=Depends(get_current_user_optional)):
    return templates.TemplateResponse("about.html", {
        "request": request,
        "current_user": user,
    })


@router.get("/contact", response_class=HTMLResponse)
def contact_page(request: Request, user=Depends(get_current_user_optional)):
    return templates.TemplateResponse("contact.html", {
        "request": request,
        "current_user": user,
        "submitted": False,
    })


@router.post("/contact", response_class=HTMLResponse)
def contact_submit(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    subject: str = Form(...),
    message: str = Form(...),
    user=Depends(get_current_user_optional),
):
    # For now, just acknowledge receipt. Real implementation would store or email.
    return templates.TemplateResponse("contact.html", {
        "request": request,
        "current_user": user,
        "submitted": True,
    })


@router.get("/profile", response_class=HTMLResponse)
def profile(
    request: Request,
    user: User = Depends(get_current_user),
):
    return templates.TemplateResponse("profile.html", {
        "request": request,
        "current_user": user,
        "user": user,
    })
