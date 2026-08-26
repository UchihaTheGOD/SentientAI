"""Public-facing routes — homepage, about, contact, profile."""
from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.models.blog_post import BlogPost
from app.services.auth_service import get_current_user, get_current_user_optional

router = APIRouter(tags=["public"])
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
def index(
    request: Request,
    user=Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    # Get latest published blog posts for homepage
    latest_posts = (
        db.query(BlogPost)
        .filter(BlogPost.published == True)
        .order_by(BlogPost.created_at.desc())
        .limit(3)
        .all()
    )

    return templates.TemplateResponse("index.html", {
        "request": request,
        "current_user": user,
        "latest_posts": latest_posts,
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
