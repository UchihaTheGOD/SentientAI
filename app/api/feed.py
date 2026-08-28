"""Feed and search routes for the public community platform."""
from fastapi import APIRouter, Request, Depends, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, desc

from app.database import get_db
from app.models.user import User
from app.models.blog_post import BlogPost, BLOG_CATEGORIES
from app.models.social import PostLike, Follow, Bookmark
from app.models.tag import Tag
from app.services.auth_service import get_current_user, get_current_user_optional

router = APIRouter(tags=["feed"])
templates = Jinja2Templates(directory="app/templates")


def _post_like_counts(db: Session, post_ids: list) -> dict:
    """Return {post_id: like_count} for a list of post IDs."""
    if not post_ids:
        return {}
    rows = (
        db.query(PostLike.post_id, func.sum(PostLike.value).label("score"))
        .filter(PostLike.post_id.in_(post_ids), PostLike.value == 1)
        .group_by(PostLike.post_id)
        .all()
    )
    return {r.post_id: r.score for r in rows}


def _user_bookmarks(db: Session, user_id: int, post_ids: list) -> set:
    if not post_ids or not user_id:
        return set()
    rows = db.query(Bookmark.post_id).filter(
        Bookmark.user_id == user_id, Bookmark.post_id.in_(post_ids)
    ).all()
    return {r.post_id for r in rows}


def _user_likes(db: Session, user_id: int, post_ids: list) -> dict:
    if not post_ids or not user_id:
        return {}
    rows = db.query(PostLike.post_id, PostLike.value).filter(
        PostLike.user_id == user_id, PostLike.post_id.in_(post_ids)
    ).all()
    return {r.post_id: r.value for r in rows}


# ---------------------------------------------------------------------------
# Explore — public trending/recent posts
# ---------------------------------------------------------------------------

@router.get("/explore", response_class=HTMLResponse)
def explore(
    request: Request,
    sort: str = Query("latest", enum=["latest", "popular", "trending"]),
    category: str = Query(""),
    tag: str = Query(""),
    user=Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    query = db.query(BlogPost).filter(BlogPost.published == True)

    if category and category in BLOG_CATEGORIES:
        query = query.filter(BlogPost.category == category)

    if tag:
        tag_obj = db.query(Tag).filter(Tag.slug == tag).first()
        if tag_obj:
            query = query.filter(BlogPost.tags.any(Tag.id == tag_obj.id))

    if sort == "popular":
        # Join with likes for score
        query = query.outerjoin(
            PostLike, (PostLike.post_id == BlogPost.id) & (PostLike.value == 1)
        ).group_by(BlogPost.id).order_by(func.count(PostLike.id).desc())
    elif sort == "trending":
        # Views as trending proxy (simple but works)
        query = query.order_by(desc(BlogPost.views))
    else:
        query = query.order_by(desc(BlogPost.created_at))

    posts = query.limit(24).all()
    post_ids = [p.id for p in posts]
    like_counts = _post_like_counts(db, post_ids)
    user_likes_map = _user_likes(db, user.id if user else None, post_ids)
    bookmarks = _user_bookmarks(db, user.id if user else None, post_ids)

    # Popular tags
    popular_tags = (
        db.query(Tag, func.count(Tag.id).label("cnt"))
        .join(Tag.posts)
        .filter(BlogPost.published == True)
        .group_by(Tag.id)
        .order_by(desc("cnt"))
        .limit(20)
        .all()
    )

    return templates.TemplateResponse("explore.html", {
        "request": request,
        "current_user": user,
        "posts": posts,
        "sort": sort,
        "active_category": category,
        "active_tag": tag,
        "like_counts": like_counts,
        "user_likes_map": user_likes_map,
        "bookmarks": bookmarks,
        "categories": BLOG_CATEGORIES,
        "popular_tags": popular_tags,
    })


# ---------------------------------------------------------------------------
# Feed — authenticated, personalized
# ---------------------------------------------------------------------------

@router.get("/feed", response_class=HTMLResponse)
def feed(
    request: Request,
    sort: str = Query("latest", enum=["latest", "popular"]),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Get IDs of users this person follows
    followed_ids = [
        r.followed_id for r in
        db.query(Follow.followed_id).filter(Follow.follower_id == user.id).all()
    ]

    # Posts from followed users
    if followed_ids:
        followed_query = (
            db.query(BlogPost)
            .filter(BlogPost.published == True, BlogPost.user_id.in_(followed_ids))
        )
        if sort == "popular":
            followed_query = followed_query.outerjoin(
                PostLike, (PostLike.post_id == BlogPost.id) & (PostLike.value == 1)
            ).group_by(BlogPost.id).order_by(func.count(PostLike.id).desc())
        else:
            followed_query = followed_query.order_by(desc(BlogPost.created_at))
        followed_posts = followed_query.limit(20).all()
    else:
        followed_posts = []

    # Recommended — recent popular posts not from followed users (or own)
    exclude_ids = followed_ids + [user.id]
    recommended = (
        db.query(BlogPost)
        .filter(BlogPost.published == True, ~BlogPost.user_id.in_(exclude_ids))
        .order_by(desc(BlogPost.views))
        .limit(10)
        .all()
    )

    all_posts = followed_posts + recommended
    post_ids = [p.id for p in all_posts]
    like_counts = _post_like_counts(db, post_ids)
    user_likes_map = _user_likes(db, user.id, post_ids)
    bookmarks = _user_bookmarks(db, user.id, post_ids)

    return templates.TemplateResponse("feed.html", {
        "request": request,
        "current_user": user,
        "followed_posts": followed_posts,
        "recommended": recommended,
        "sort": sort,
        "like_counts": like_counts,
        "user_likes_map": user_likes_map,
        "bookmarks": bookmarks,
        "following_count": len(followed_ids),
    })


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

@router.get("/search", response_class=HTMLResponse)
def search(
    request: Request,
    q: str = Query(""),
    kind: str = Query("posts", enum=["posts", "users", "tags"]),
    user=Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    q = q.strip()
    results_posts = []
    results_users = []
    results_tags = []

    if q:
        if kind == "posts" or not kind:
            results_posts = (
                db.query(BlogPost)
                .filter(
                    BlogPost.published == True,
                    or_(
                        BlogPost.title.ilike(f"%{q}%"),
                        BlogPost.summary.ilike(f"%{q}%"),
                        BlogPost.content.ilike(f"%{q}%"),
                    )
                )
                .order_by(desc(BlogPost.views))
                .limit(20)
                .all()
            )

        if kind == "users":
            results_users = (
                db.query(User)
                .filter(
                    User.is_active == True,
                    or_(
                        User.username.ilike(f"%{q}%"),
                        User.display_name.ilike(f"%{q}%"),
                        User.bio.ilike(f"%{q}%"),
                    )
                )
                .limit(20)
                .all()
            )

        if kind == "tags":
            results_tags = (
                db.query(Tag)
                .filter(Tag.name.ilike(f"%{q}%"))
                .limit(20)
                .all()
            )

    # Trending tags for empty state / sidebar
    trending_tags = (
        db.query(Tag, func.count(Tag.id).label("cnt"))
        .join(Tag.posts)
        .filter(BlogPost.published == True)
        .group_by(Tag.id)
        .order_by(desc("cnt"))
        .limit(15)
        .all()
    )

    return templates.TemplateResponse("search.html", {
        "request": request,
        "current_user": user,
        "q": q,
        "kind": kind,
        "results_posts": results_posts,
        "results_users": results_users,
        "results_tags": results_tags,
        "trending_tags": trending_tags,
    })
