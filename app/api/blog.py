"""Blog routes — listing and individual posts."""
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.blog_post import BlogPost, BLOG_CATEGORIES
from app.services.auth_service import get_current_user_optional

router = APIRouter(tags=["blog"])
templates = Jinja2Templates(directory="app/templates")


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

    return templates.TemplateResponse("blog/post.html", {
        "request": request,
        "current_user": user,
        "post": post,
    })
