"""Single shared Jinja2 environment.

Every router imports `templates` from here so that filters and globals
(CSRF tokens, safe content rendering, notification badge) are registered
exactly once and are available in every template.
"""
from __future__ import annotations

import jinja2
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape

from app.services.sanitize import clean_text, render_content, safe_url, strip_formatting

templates = Jinja2Templates(directory="app/templates")


# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------

@jinja2.pass_context
def csrf_token(context) -> str:
    request = context.get("request")
    return getattr(request.state, "csrf_token", "") if request else ""


@jinja2.pass_context
def csrf_input(context) -> Markup:
    """Hidden input every state-changing form must include."""
    token = csrf_token(context)
    return Markup(f'<input type="hidden" name="csrf_token" value="{escape(token)}">')


@jinja2.pass_context
def unread_notifications(context) -> int:
    """Unread notification count for the header badge (0 when anonymous)."""
    user = context.get("current_user") or context.get("user")
    if not user or not getattr(user, "id", None):
        return 0
    from app.database import SessionLocal
    from app.models.social import Notification

    db = SessionLocal()
    try:
        return (
            db.query(Notification)
            .filter(Notification.user_id == user.id, Notification.is_read == False)  # noqa: E712
            .count()
        )
    except Exception:
        return 0
    finally:
        db.close()


@jinja2.pass_context
def canonical_url(context, path: str | None = None) -> str:
    request = context.get("request")
    if not request:
        return path or ""
    base = f"{request.url.scheme}://{request.url.netloc}"
    return base + (path if path is not None else request.url.path)


def query_string(params: dict, **overrides) -> str:
    """Build a querystring from existing params plus overrides (for pagination)."""
    from urllib.parse import urlencode

    merged = {k: v for k, v in (params or {}).items() if v not in (None, "", 0)}
    for key, value in overrides.items():
        if value in (None, ""):
            merged.pop(key, None)
        else:
            merged[key] = value
    return ("?" + urlencode(merged)) if merged else ""


templates.env.globals["csrf_input"] = csrf_input
templates.env.globals["csrf_token"] = csrf_token
templates.env.globals["unread_notifications"] = unread_notifications
templates.env.globals["canonical_url"] = canonical_url
templates.env.globals["query_string"] = query_string

templates.env.filters["content"] = render_content
templates.env.filters["plain"] = strip_formatting
templates.env.filters["safe_url"] = safe_url
templates.env.filters["clean"] = clean_text
