"""CSRF protection for HTML form posts.

Signed double-submit cookie:
  * A random token is signed with SECRET_KEY and stored in the httpOnly
    `csrf_token` cookie.
  * Every state-changing HTML form must echo the same value back in a
    `csrf_token` field (templates do this via the `csrf_input()` global) or an
    `X-CSRF-Token` header for fetch/XHR callers.
  * The middleware rejects unsafe methods when the two do not match.

The cookie is httpOnly, so a cross-origin page cannot read the token, and the
signature means an attacker cannot mint one.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.config import settings

COOKIE_NAME = "csrf_token"
FORM_FIELD = "csrf_token"
HEADER_NAME = "x-csrf-token"

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

# Paths that legitimately receive machine-to-machine POSTs and authenticate by
# other means. Kept deliberately tiny.
EXEMPT_PREFIXES: tuple[str, ...] = ("/api/health",)


def _sign(raw: str) -> str:
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256
    ).hexdigest()[:32]


def generate_token() -> str:
    raw = secrets.token_urlsafe(24)
    return f"{raw}.{_sign(raw)}"


def token_is_wellformed(token: str | None) -> bool:
    if not token or "." not in token or len(token) > 200:
        return False
    raw, _, signature = token.rpartition(".")
    if not raw or not signature:
        return False
    return hmac.compare_digest(_sign(raw), signature)


def set_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.ENVIRONMENT == "production",
        max_age=60 * 60 * 12,
        path="/",
    )


class CSRFMiddleware(BaseHTTPMiddleware):
    """Issues a CSRF token on safe requests and enforces it on unsafe ones."""

    async def dispatch(self, request: Request, call_next):
        cookie_token = request.cookies.get(COOKIE_NAME)
        token = cookie_token if token_is_wellformed(cookie_token) else generate_token()
        request.state.csrf_token = token
        needs_cookie = token != cookie_token

        method = request.method.upper()
        exempt = request.url.path.startswith(EXEMPT_PREFIXES)

        if method not in SAFE_METHODS and not exempt:
            submitted = request.headers.get(HEADER_NAME)
            if not submitted:
                content_type = request.headers.get("content-type", "")
                if content_type.startswith(
                    ("application/x-www-form-urlencoded", "multipart/form-data")
                ):
                    try:
                        # Buffer the body before parsing the form. Under
                        # Starlette's BaseHTTPMiddleware, calling request.body()
                        # here caches the bytes so the very same body is
                        # replayed to the downstream endpoint; calling
                        # request.form() *without* this only drains the receive
                        # stream, and the route then parses an empty body — so
                        # every real browser form POST (token in a hidden field
                        # rather than the X-CSRF-Token header) would 422.
                        await request.body()
                        form = await request.form()
                        raw = form.get(FORM_FIELD)
                        submitted = raw if isinstance(raw, str) else None
                    except Exception:
                        submitted = None

            valid = (
                token_is_wellformed(cookie_token)
                and isinstance(submitted, str)
                and hmac.compare_digest(submitted, cookie_token or "")
            )
            if not valid:
                from app.services.errors import csrf_failure_response

                response = csrf_failure_response(request)
                set_cookie(response, token)
                return response

        response = await call_next(request)
        if needs_cookie:
            set_cookie(response, token)
        return response
