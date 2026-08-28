"""Community routes — user profiles, dashboard, activity, community feed."""
from fastapi import APIRouter, Request, Depends, Form, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.user import User
from app.models.blog_post import BlogPost
from app.models.activity import Activity
from app.models.lab_session import LabSession
from app.models.security_event import SecurityEvent
from app.models.social import Follow, Bookmark
from app.services.auth_service import get_current_user, get_current_user_optional
from app.services.activity_service import (
    get_user_activities,
    get_recent_public_activities,
    log_activity,
)

router = APIRouter(tags=["community"])
templates = Jinja2Templates(directory="app/templates")


# ---- Public community routes ----

@router.get("/community", response_class=HTMLResponse)
def community_feed(
    request: Request,
    user=Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Community feed showing recent public activity and top contributors."""
    recent_activities = get_recent_public_activities(db, limit=30)

    # Resolve user objects for activities
    user_ids = list({a.user_id for a in recent_activities})
    users_map = {}
    if user_ids:
        for u in db.query(User).filter(User.id.in_(user_ids)).all():
            users_map[u.id] = u

    # Recent published posts
    recent_posts = (
        db.query(BlogPost)
        .filter(BlogPost.published == True)
        .order_by(BlogPost.created_at.desc())
        .limit(6)
        .all()
    )

    # Top contributors (users with most published posts)
    top_contributors = (
        db.query(User, func.count(BlogPost.id).label("post_count"))
        .join(BlogPost, BlogPost.user_id == User.id)
        .filter(BlogPost.published == True)
        .group_by(User.id)
        .order_by(func.count(BlogPost.id).desc())
        .limit(10)
        .all()
    )

    return templates.TemplateResponse("community.html", {
        "request": request,
        "current_user": user,
        "recent_activities": recent_activities,
        "users_map": users_map,
        "recent_posts": recent_posts,
        "top_contributors": top_contributors,
    })


@router.get("/users/{username}", response_class=HTMLResponse)
@router.get("/u/{username}", response_class=HTMLResponse)
def public_profile(
    username: str,
    request: Request,
    user=Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Public user profile showing bio, published posts, and public activity."""
    profile_user = db.query(User).filter(User.username == username).first()
    if not profile_user:
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

    # Published posts by this user
    user_posts = (
        db.query(BlogPost)
        .filter(BlogPost.user_id == profile_user.id, BlogPost.published == True)
        .order_by(BlogPost.created_at.desc())
        .limit(20)
        .all()
    )

    # Public activity
    public_activity = get_user_activities(db, profile_user.id, public_only=True, limit=20)

    # Social stats
    followers_count = db.query(func.count(Follow.id)).filter(
        Follow.followed_id == profile_user.id
    ).scalar() or 0
    following_count = db.query(func.count(Follow.id)).filter(
        Follow.follower_id == profile_user.id
    ).scalar() or 0

    # Is the viewing user following this profile?
    is_following = False
    if user and user.id != profile_user.id:
        is_following = db.query(Follow).filter(
            Follow.follower_id == user.id, Follow.followed_id == profile_user.id
        ).first() is not None

    # Lab stats (public summary — no private details)
    lab_sessions_count = (
        db.query(func.count(LabSession.id))
        .filter(LabSession.user_id == profile_user.id)
        .scalar() or 0
    )

    return templates.TemplateResponse("profile_public.html", {
        "request": request,
        "current_user": user,
        "profile_user": profile_user,
        "user_posts": user_posts,
        "public_activity": public_activity,
        "lab_sessions_count": lab_sessions_count,
        "followers_count": followers_count,
        "following_count": following_count,
        "is_following": is_following,
    })


# ---- Authenticated routes ----

@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Authenticated user dashboard — activity, posts, lab progress."""
    # User's recent activity (all, not just public)
    recent_activity = get_user_activities(db, user.id, public_only=False, limit=20)

    # User's posts (published + drafts)
    my_posts = (
        db.query(BlogPost)
        .filter(BlogPost.user_id == user.id)
        .order_by(BlogPost.created_at.desc())
        .limit(10)
        .all()
    )

    # Lab progress
    lab_sessions = (
        db.query(LabSession)
        .filter(LabSession.user_id == user.id)
        .order_by(LabSession.started_at.desc())
        .limit(10)
        .all()
    )

    # Stats
    total_posts = db.query(func.count(BlogPost.id)).filter(BlogPost.user_id == user.id).scalar() or 0
    total_sessions = db.query(func.count(LabSession.id)).filter(LabSession.user_id == user.id).scalar() or 0
    total_events = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.user_id == user.id).scalar() or 0

    return templates.TemplateResponse("dashboard_user.html", {
        "request": request,
        "current_user": user,
        "recent_activity": recent_activity,
        "my_posts": my_posts,
        "lab_sessions": lab_sessions,
        "total_posts": total_posts,
        "total_sessions": total_sessions,
        "total_events": total_events,
    })


@router.get("/profile/edit", response_class=HTMLResponse)
def edit_profile_form(
    request: Request,
    user: User = Depends(get_current_user),
):
    return templates.TemplateResponse("profile_edit.html", {
        "request": request,
        "current_user": user,
        "errors": [],
        "success": False,
    })


@router.post("/profile/edit", response_class=HTMLResponse)
def edit_profile_submit(
    request: Request,
    display_name: str = Form(""),
    bio: str = Form(""),
    website: str = Form(""),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    errors = []

    if display_name and len(display_name.strip()) > 100:
        errors.append("Display name must be under 100 characters.")
    if bio and len(bio.strip()) > 500:
        errors.append("Bio must be under 500 characters.")
    if website and len(website.strip()) > 255:
        errors.append("Website URL too long.")
    if website and not website.strip().startswith(("http://", "https://", "")):
        errors.append("Website must start with http:// or https://")

    if errors:
        return templates.TemplateResponse("profile_edit.html", {
            "request": request,
            "current_user": user,
            "errors": errors,
            "success": False,
        })

    user.display_name = display_name.strip() or None
    user.bio = bio.strip() or None
    user.website = website.strip() or None
    db.commit()

    log_activity(db, user.id, "profile_updated", "Updated profile information", is_public=False)

    return templates.TemplateResponse("profile_edit.html", {
        "request": request,
        "current_user": user,
        "errors": [],
        "success": True,
    })
