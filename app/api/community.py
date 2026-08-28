"""Community routes — user profiles, dashboard, activity, community feed."""
from fastapi import APIRouter, Request, Depends, Form, HTTPException, Query, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models.user import User
from app.models.blog_post import POST_PUBLISHED, BlogPost
from app.models.activity import ACTIVITY_TYPES, Activity
from app.models.lab_session import LabSession
from app.models.security_event import SecurityEvent
from app.models.social import Follow, Bookmark
from app.services.auth_service import get_current_user, get_current_user_optional
from app.services.activity_service import (
    get_user_activities,
    get_recent_public_activities,
    log_activity,
)
from app.services.content import public_posts_query
from app.services.pagination import paginate
from app.services.sanitize import clean_text, safe_url
from app.template_env import templates

router = APIRouter(tags=["community"])


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
        public_posts_query(db)
        .order_by(BlogPost.created_at.desc())
        .limit(6)
        .all()
    )

    # Top contributors (users with most published posts)
    top_contributors = (
        db.query(User, func.count(BlogPost.id).label("post_count"))
        .join(BlogPost, BlogPost.user_id == User.id)
        .filter(
            BlogPost.status == POST_PUBLISHED,
            BlogPost.is_hidden == False,  # noqa: E712
            User.is_suspended == False,  # noqa: E712
        )
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
        public_posts_query(db)
        .filter(BlogPost.user_id == profile_user.id)
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


@router.get("/me", response_class=HTMLResponse)
def my_profile(user: User = Depends(get_current_user)):
    """Shorthand for "my public profile" — used by the nav and by e-mail links,
    so the username does not have to be interpolated by the caller."""
    return RedirectResponse(f"/u/{user.username}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/activity", response_class=HTMLResponse)
def my_activity(
    request: Request,
    page: int = Query(1, ge=1),
    kind: str = Query("", max_length=50),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The signed-in user's own activity log, public entries and private alike.

    Scoped to `user.id` in the query itself rather than filtered afterwards:
    this is the whole record of one account's actions, including the private
    entries a visitor to the public profile never sees.
    """
    query = db.query(Activity).filter(Activity.user_id == user.id)

    # An unknown `kind` narrows to nothing rather than being ignored, so a typo
    # in the querystring cannot silently widen the result.
    selected_kind = kind if kind in ACTIVITY_TYPES else ""
    if selected_kind:
        query = query.filter(Activity.activity_type == selected_kind)

    activity_page = paginate(
        query.order_by(Activity.created_at.desc(), Activity.id.desc()),
        page=page,
        per_page=25,
    )

    # Only the types this account actually has, so the filter row is never a
    # wall of options that all return nothing.
    used_kinds = [
        row[0] for row in db.query(Activity.activity_type)
        .filter(Activity.user_id == user.id)
        .group_by(Activity.activity_type)
        .order_by(func.count(Activity.id).desc())
        .all()
    ]

    return templates.TemplateResponse("activity.html", {
        "request": request,
        "current_user": user,
        "page": activity_page,
        "activities": activity_page.items,
        "used_kinds": used_kinds,
        "selected_kind": selected_kind,
        "params": {"kind": selected_kind} if selected_kind else {},
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

    # SECURITY: normalise before validating. `clean_text` strips control
    # characters, which is what stops "java\tscript:..." style scheme hiding
    # from slipping past the check below.
    display_name = clean_text(display_name, 100)
    bio = clean_text(bio, 500)
    website_raw = clean_text(website, 255)

    if len(display_name) > 100:
        errors.append("Display name must be under 100 characters.")
    if len(bio) > 500:
        errors.append("Bio must be under 500 characters.")

    # The previous check was `startswith(("http://", "https://", ""))`, which
    # every string satisfies because of the empty prefix — so "javascript:..."
    # was stored and later rendered into an href. `safe_url` is the real check.
    website_clean = ""
    if website_raw:
        website_clean = safe_url(website_raw, allow_relative=False)
        if not website_clean:
            errors.append("Website must be a full http:// or https:// address.")

    if errors:
        return templates.TemplateResponse("profile_edit.html", {
            "request": request,
            "current_user": user,
            "errors": errors,
            "success": False,
        })

    user.display_name = display_name or None
    user.bio = bio or None
    user.website = website_clean or None
    db.commit()

    log_activity(db, user.id, "profile_updated", "Updated profile information", is_public=False)

    return templates.TemplateResponse("profile_edit.html", {
        "request": request,
        "current_user": user,
        "errors": [],
        "success": True,
    })
