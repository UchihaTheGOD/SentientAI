"""Blog routes — listing, reading, writing and the post lifecycle.

Visibility is decided in one place (`app/services/content.py`), not per route:
the listing pages only ever show published, unhidden posts, and the single-post
page defers to `can_view_post`, so an author can preview their own draft while
everyone else gets a plain 404 rather than a hint that the post exists.

Post bodies are stored exactly as the author typed them and rendered through the
`content` filter (escape-first, then a small Markdown subset) — no template in
this package uses `| safe` on user text.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.blog_post import (
    BLOG_CATEGORIES,
    POST_ARCHIVED,
    POST_DRAFT,
    POST_PUBLISHED,
    BlogPost,
)
from app.models.social import Bookmark, Comment, CommentLike, PostLike
from app.models.tag import Tag
from app.models.user import User
from app.services import audit, tags as tag_service
from app.services import admin_service
from app.services.activity_service import log_activity
from app.services.auth_service import get_current_user, get_current_user_optional
from app.services.content import (
    can_edit_post,
    can_view_post,
    post_card_context,
    public_posts_query,
    visible_comments_query,
)
from app.services.pagination import clamp_page, paginate
from app.services.ratelimit import limit_post_write
from app.services.sanitize import clean_text
from app.template_env import templates

router = APIRouter(tags=["blog"])

MAX_TITLE = 300
MIN_TITLE = 5
MAX_SUMMARY = 300
MAX_CONTENT = 100_000
MIN_CONTENT = 20
PER_PAGE = 10

# What the "Save draft / Publish / Archive" buttons may ask for.
POST_ACTIONS = {"draft": POST_DRAFT, "publish": POST_PUBLISHED, "archive": POST_ARCHIVED}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _slugify(text: str) -> str:
    """Generate a URL-safe slug from a title."""
    slug = (text or "").lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug[:190] or "post"


def _unique_slug(db: Session, title: str, exclude_id: int | None = None) -> str:
    base = _slugify(title)
    slug = base
    counter = 1
    while True:
        clash = db.query(BlogPost.id).filter(BlogPost.slug == slug)
        if exclude_id is not None:
            clash = clash.filter(BlogPost.id != exclude_id)
        if clash.first() is None:
            return slug
        slug = f"{base}-{counter}"
        counter += 1


def _estimate_reading_time(content: str) -> int:
    """Reading time in minutes (~200 wpm)."""
    return max(1, round(len((content or "").split()) / 200))


def _validate(title: str, category: str, content: str) -> list[str]:
    """Field validation shared by create and edit. Returns human-readable errors."""
    errors: list[str] = []
    if len(title.strip()) < MIN_TITLE:
        errors.append(f"Title must be at least {MIN_TITLE} characters.")
    if len(title.strip()) > MAX_TITLE:
        errors.append(f"Title must be under {MAX_TITLE} characters.")
    # Whitelist check — the category is echoed back into pages, so it may only
    # ever be one of ours. The public site offers the community categories only;
    # RESEARCH_CATEGORIES belongs to the testing area, and letting it through
    # here would put lab vocabulary on public pages.
    if category not in BLOG_CATEGORIES:
        errors.append("Choose one of the listed categories.")
    if len(content.strip()) < MIN_CONTENT:
        errors.append(f"Post content must be at least {MIN_CONTENT} characters.")
    if len(content) > MAX_CONTENT:
        errors.append("This post is too long to save.")
    return errors


def _owned_post(db: Session, slug: str, user: User) -> BlogPost:
    """The post plus an authorization check. 404 when it doesn't exist, 403 when
    it isn't the caller's to change — enforced here, not by hiding the button."""
    post = db.query(BlogPost).filter(BlogPost.slug == slug).first()
    if post is None:
        raise HTTPException(status_code=404, detail="Post not found")
    if not can_edit_post(post, user):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You can only change your own posts.")
    return post


def _newest_first(query):
    """Order by publication date, falling back to creation date.

    `coalesce` rather than `NULLS LAST` so the ordering behaves the same on the
    SQLite build shipped with any supported Python.
    """
    return query.order_by(
        func.coalesce(BlogPost.published_at, BlogPost.created_at).desc(),
        BlogPost.id.desc(),
    )


def _related_posts(db: Session, post: BlogPost, limit: int = 4) -> list[BlogPost]:
    """Posts sharing a tag, topped up by category. Public rows only."""
    tag_ids = [t.id for t in (post.tags or [])]
    found: list[BlogPost] = []
    seen = {post.id}

    if tag_ids:
        rows = _newest_first(
            public_posts_query(db).filter(
                BlogPost.id != post.id, BlogPost.tags.any(Tag.id.in_(tag_ids))
            )
        ).limit(limit).all()
        for row in rows:
            found.append(row)
            seen.add(row.id)

    if len(found) < limit:
        rows = (
            public_posts_query(db)
            .filter(BlogPost.category == post.category, BlogPost.id.notin_(seen))
            .order_by(BlogPost.views.desc(), BlogPost.created_at.desc())
            .limit(limit - len(found))
            .all()
        )
        found.extend(rows)
    return found


def _sorted_public(db: Session, sort: str):
    query = public_posts_query(db)
    if sort == "popular":
        return query.order_by(BlogPost.views.desc(), BlogPost.id.desc())
    return _newest_first(query)


# ---------------------------------------------------------------------------
# Public listing
# ---------------------------------------------------------------------------

def _listing(request: Request, db: Session, user, *, page: int, sort: str,
             category: str = "", tag: Tag | None = None,
             heading: str, lead: str, params: dict):
    """One renderer for /blog, /category/{c} and /tag/{s} so the three pages
    can't drift apart."""
    sort = sort if sort in ("recent", "popular") else "recent"
    query = _sorted_public(db, sort)
    if category:
        query = query.filter(BlogPost.category == category)
    if tag is not None:
        query = query.filter(BlogPost.tags.any(Tag.id == tag.id))

    paged = paginate(query, clamp_page(page), PER_PAGE)
    cards = post_card_context(db, paged.items)

    return templates.TemplateResponse("blog/index.html", {
        "request": request,
        "current_user": user,
        "posts": paged.items,
        "page": paged,
        "params": params,
        "heading": heading,
        "lead": lead,
        "categories": BLOG_CATEGORIES,
        "active_category": category or None,
        "active_tag": tag,
        "sort": sort,
        **cards,
    })


@router.get("/blog", response_class=HTMLResponse)
def blog_index(
    request: Request,
    category: str = "",
    sort: str = "recent",
    page: int = 1,
    user=Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    # An unknown category is dropped rather than echoed back into the page.
    active = category if category in BLOG_CATEGORIES else ""
    return _listing(
        request, db, user, page=page, sort=sort, category=active,
        heading=active or "Blog",
        lead=(f"Posts in {active}." if active
              else "Articles, essays and ideas from the community."),
        params={"category": active, "sort": sort if sort == "popular" else ""},
    )


@router.get("/category/{category}", response_class=HTMLResponse)
def category_page(
    category: str,
    request: Request,
    sort: str = "recent",
    page: int = 1,
    user=Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    if category not in BLOG_CATEGORIES:
        return templates.TemplateResponse(
            "404.html", {"request": request, "current_user": user}, status_code=404)
    return _listing(
        request, db, user, page=page, sort=sort, category=category,
        heading=category, lead=f"Everything filed under {category}.",
        params={"sort": sort if sort == "popular" else ""},
    )


@router.get("/tag/{slug}", response_class=HTMLResponse)
def tag_page(
    slug: str,
    request: Request,
    sort: str = "recent",
    page: int = 1,
    user=Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    tag = db.query(Tag).filter(Tag.slug == tag_service.slugify_tag(slug.lower())).first()
    if tag is None:
        return templates.TemplateResponse(
            "404.html", {"request": request, "current_user": user}, status_code=404)
    return _listing(
        request, db, user, page=page, sort=sort, tag=tag,
        heading=f"#{tag.name}", lead=f"Posts tagged {tag.name}.",
        params={"sort": sort if sort == "popular" else ""},
    )


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

def _write_form(request: Request, user: User, *, post=None, tags_field: str = "",
                errors: list[str] | None = None, status_code: int = 200):
    return templates.TemplateResponse("blog/write.html", {
        "request": request,
        "current_user": user,
        "categories": BLOG_CATEGORIES,
        "post": post,
        "tags_field": tags_field,
        "errors": errors or [],
        "max_tags": tag_service.MAX_TAGS_PER_POST,
    }, status_code=status_code)


@router.get("/write", response_class=HTMLResponse)
def write_post_form(request: Request, user: User = Depends(get_current_user)):
    return _write_form(request, user)


@router.post("/write", response_class=HTMLResponse,
             dependencies=[Depends(limit_post_write)])
def write_post_submit(
    request: Request,
    title: str = Form(...),
    category: str = Form(...),
    content: str = Form(...),
    summary: str = Form(""),
    tags: str = Form(""),
    action: str = Form("draft"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a post. A single `action` field decides the state, so there is no
    way for a checkbox and a submit button to disagree about publishing."""
    title = clean_text(title, MAX_TITLE)
    summary = clean_text(summary, MAX_SUMMARY)
    state = POST_ACTIONS.get(action, POST_DRAFT)
    if state == POST_ARCHIVED:  # nothing to archive yet
        state = POST_DRAFT

    errors = _validate(title, category, content)
    if errors:
        return _write_form(
            request, user,
            post={"title": title, "category": category, "content": content,
                  "summary": summary},
            tags_field=tags, errors=errors, status_code=400,
        )

    post = BlogPost(
        title=title.strip(),
        slug=_unique_slug(db, title),
        author=user.display,
        user_id=user.id,
        category=category,
        summary=summary.strip(),
        content=content.strip(),
        reading_time=_estimate_reading_time(content),
    )
    post.apply_state(state)
    post.tags = tag_service.get_or_create_tags(db, tag_service.parse_tags(tags))
    db.add(post)
    db.commit()
    db.refresh(post)

    published = state == POST_PUBLISHED
    log_activity(
        db, user.id,
        "blog_post_published" if published else "blog_post_created",
        f'{"Published" if published else "Created draft"}: {post.title}',
        target_type="blog_post", target_id=str(post.id),
        is_public=published,
    )
    audit.record(db, "post.published" if published else "post.created", user=user,
                 target_type="blog_post", target_id=post.id, request=request)
    if published:
        audit.bump_metric(db, "posts_published")

    return RedirectResponse(url=f"/blog/{post.slug}", status_code=303)


@router.get("/my/posts", response_class=HTMLResponse)
def my_posts(
    request: Request,
    state: str = "",
    page: int = 1,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The author's own posts, drafts included. Scoped to `user.id`, so this can
    never list someone else's unpublished work."""
    query = db.query(BlogPost).filter(BlogPost.user_id == user.id)
    if state in ("draft", "published", "archived"):
        query = query.filter(BlogPost.status == state)
    query = query.order_by(BlogPost.updated_at.desc(), BlogPost.id.desc())
    paged = paginate(query, clamp_page(page), 15)

    counts = dict(
        db.query(BlogPost.status, func.count(BlogPost.id))
        .filter(BlogPost.user_id == user.id)
        .group_by(BlogPost.status)
        .all()
    )
    return templates.TemplateResponse("blog/my_posts.html", {
        "request": request,
        "current_user": user,
        "posts": paged.items,
        "page": paged,
        "params": {"state": state},
        "active_state": state,
        "counts": counts,
        "total": sum(counts.values()),
    })


# ---------------------------------------------------------------------------
# Editing / lifecycle
# ---------------------------------------------------------------------------

@router.get("/blog/{slug}/edit", response_class=HTMLResponse)
def edit_post_form(
    slug: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    post = _owned_post(db, slug, user)
    return _write_form(request, user, post=post,
                       tags_field=tag_service.tags_to_field(post.tags))


@router.post("/blog/{slug}/edit", response_class=HTMLResponse,
             dependencies=[Depends(limit_post_write)])
def edit_post_submit(
    slug: str,
    request: Request,
    title: str = Form(...),
    category: str = Form(...),
    content: str = Form(...),
    summary: str = Form(""),
    tags: str = Form(""),
    action: str = Form("keep"),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    post = _owned_post(db, slug, user)
    title = clean_text(title, MAX_TITLE)
    summary = clean_text(summary, MAX_SUMMARY)

    errors = _validate(title, category, content)
    if errors:
        return _write_form(request, user, post=post, tags_field=tags,
                           errors=errors, status_code=400)

    was_public = post.is_public
    post.title = title.strip()
    post.category = category
    post.content = content.strip()
    post.summary = summary.strip()
    post.reading_time = _estimate_reading_time(content)
    post.tags = tag_service.get_or_create_tags(db, tag_service.parse_tags(tags))
    post.updated_at = datetime.now(timezone.utc)

    # "keep" leaves the lifecycle alone — editing a published post shouldn't
    # silently unpublish it, and editing a draft shouldn't silently publish it.
    if action in POST_ACTIONS:
        post.apply_state(POST_ACTIONS[action])
    db.commit()

    now_public = post.is_public
    if now_public and not was_public:
        log_activity(db, user.id, "blog_post_published", f"Published: {post.title}",
                     target_type="blog_post", target_id=str(post.id))
        audit.record(db, "post.published", user=user, target_type="blog_post",
                     target_id=post.id, request=request)
        audit.bump_metric(db, "posts_published")
    else:
        log_activity(db, user.id, "blog_post_updated", f"Updated: {post.title}",
                     target_type="blog_post", target_id=str(post.id),
                     is_public=now_public)
        audit.record(db, "post.updated", user=user, target_type="blog_post",
                     target_id=post.id, request=request)

    return RedirectResponse(url=f"/blog/{post.slug}", status_code=303)


@router.post("/blog/{slug}/state", dependencies=[Depends(limit_post_write)])
def change_post_state(
    slug: str,
    request: Request,
    action: str = Form(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Publish / unpublish / archive from the post page or the author's list."""
    post = _owned_post(db, slug, user)
    if action not in POST_ACTIONS:
        raise HTTPException(status_code=400, detail="Unknown action")

    new_state = POST_ACTIONS[action]
    if new_state == post.state:
        return RedirectResponse(url=f"/blog/{post.slug}", status_code=303)

    post.apply_state(new_state)
    post.updated_at = datetime.now(timezone.utc)
    db.commit()

    if new_state == POST_PUBLISHED:
        log_activity(db, user.id, "blog_post_published", f"Published: {post.title}",
                     target_type="blog_post", target_id=str(post.id))
        audit.record(db, "post.published", user=user, target_type="blog_post",
                     target_id=post.id, request=request)
    elif new_state == POST_ARCHIVED:
        audit.record(db, "post.archived", user=user, target_type="blog_post",
                     target_id=post.id, request=request)
    else:
        audit.record(db, "post.updated", user=user, target_type="blog_post",
                     target_id=post.id, detail="unpublished", request=request)

    if new_state == POST_PUBLISHED:
        return RedirectResponse(url=f"/blog/{post.slug}", status_code=303)
    return RedirectResponse(url="/my/posts", status_code=303)


@router.post("/blog/{slug}/delete", dependencies=[Depends(limit_post_write)])
def delete_post(
    slug: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Permanently remove a post the caller owns, along with the rows that only
    exist because of it. The cascade lives in one place
    (`admin_service.delete_post_cascade`) because SQLite ignores
    `ON DELETE CASCADE` unless foreign keys are switched on for the connection,
    so it has to be done by hand — and identically wherever a post is deleted."""
    post = _owned_post(db, slug, user)
    post_id, title, owner_id = post.id, post.title, post.user_id

    admin_service.delete_post_cascade(db, post)
    db.commit()

    audit.record(db, "post.deleted", user=user, target_type="blog_post",
                 target_id=post_id,
                 detail=f'{"own post" if owner_id == user.id else "admin removal"}: {title[:80]}',
                 request=request)
    return RedirectResponse(url="/my/posts", status_code=303)


# ---------------------------------------------------------------------------
# Single post — declared last so the more specific /blog/... routes win
# ---------------------------------------------------------------------------

@router.get("/blog/{slug}", response_class=HTMLResponse)
def blog_post(
    slug: str,
    request: Request,
    user=Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    post = db.query(BlogPost).filter(BlogPost.slug == slug).first()
    # One check for "may this person see this", and a 404 rather than a 403 for
    # everyone else so the page's existence isn't confirmed.
    if not can_view_post(post, user):
        return templates.TemplateResponse(
            "404.html", {"request": request, "current_user": user}, status_code=404)

    # Views count public reads by other people — an author refreshing a draft
    # preview shouldn't inflate their own numbers.
    if post.is_public and (user is None or user.id != post.user_id):
        post.views = (post.views or 0) + 1
        db.commit()

    author_user = (
        db.query(User).filter(User.id == post.user_id).first() if post.user_id else None
    )

    likes = db.query(func.count(PostLike.id)).filter(
        PostLike.post_id == post.id, PostLike.value == 1
    ).scalar() or 0
    dislikes = db.query(func.count(PostLike.id)).filter(
        PostLike.post_id == post.id, PostLike.value == -1
    ).scalar() or 0

    user_vote = None
    user_bookmarked = False
    user_following = False
    if user:
        vote_row = db.query(PostLike).filter(
            PostLike.user_id == user.id, PostLike.post_id == post.id
        ).first()
        user_vote = vote_row.value if vote_row else None
        user_bookmarked = db.query(Bookmark.id).filter(
            Bookmark.user_id == user.id, Bookmark.post_id == post.id
        ).first() is not None
        if author_user and author_user.id != user.id:
            from app.models.social import Follow

            user_following = db.query(Follow.id).filter(
                Follow.follower_id == user.id, Follow.followed_id == author_user.id
            ).first() is not None

    # Moderator-hidden comments are excluded by the query; author-deleted ones
    # are kept so a thread doesn't lose its replies, and render as a placeholder.
    visible = visible_comments_query(db, post.id).order_by(Comment.created_at.asc()).all()
    top_comments = [c for c in visible if c.parent_id is None]
    reply_map: dict[int, list[Comment]] = {}
    for comment in visible:
        if comment.parent_id is not None:
            reply_map.setdefault(comment.parent_id, []).append(comment)

    # A deleted top-level comment with no surviving replies is just noise.
    top_comments = [
        c for c in top_comments if not c.is_deleted or reply_map.get(c.id)
    ]
    comment_count = sum(1 for c in visible if not c.is_deleted)

    author_ids = {c.user_id for c in visible}
    comment_users = (
        {u.id: u for u in db.query(User).filter(User.id.in_(author_ids)).all()}
        if author_ids else {}
    )

    return templates.TemplateResponse("blog/post.html", {
        "request": request,
        "current_user": user,
        "post": post,
        "author_user": author_user,
        "likes": likes,
        "dislikes": dislikes,
        "user_vote": user_vote,
        "user_bookmarked": user_bookmarked,
        "user_following": user_following,
        "top_comments": top_comments,
        "reply_map": reply_map,
        "comment_users": comment_users,
        "comment_count": comment_count,
        "related_posts": _related_posts(db, post),
        "can_edit": can_edit_post(post, user),
    })

