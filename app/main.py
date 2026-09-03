"""SentientAI — Main FastAPI application.

A community publishing platform: a public reading and writing site (`/`,
`/explore`, `/blog`, `/community`, `/u/...`) that is browsable anonymously,
plus a private `/admin` panel reachable only by administrators.

Middleware order matters. `add_middleware` puts the newest layer outermost, so
the registration order below produces:

    SecurityHeaders  →  CSRF  →  routes

which means the CSRF rejection response still gets security headers.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from app.database import init_db
from app.services import errors
from app.services.csrf import CSRFMiddleware

logger = logging.getLogger("sentientai")


# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        # Content-Security-Policy is a second line of defence behind
        # app/services/sanitize.py: even if markup slipped through, inline
        # <script> would not execute. 'unsafe-inline' is still required for
        # style attributes used throughout the templates.
        response.headers.setdefault("Content-Security-Policy", "; ".join([
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com",
            "img-src 'self' data: https:",
            "connect-src 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "object-src 'none'",
        ]))
        return response


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(application: FastAPI):
    init_db()
    yield


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    application = FastAPI(
        title="Sentient",
        description="Community publishing platform with a private administration panel.",
        version="0.3.0",
        docs_url="/api/docs",
        redoc_url=None,
        lifespan=lifespan,
    )

    # Innermost first: CSRF needs request.state before handlers run, security
    # headers must wrap everything including CSRF rejections.
    application.add_middleware(CSRFMiddleware)
    application.add_middleware(SecurityHeadersMiddleware)

    application.mount("/static", StaticFiles(directory="app/static"), name="static")

    from app.api import (
        admin, auth, blog, community, feed, health, messages, moderation,
        social, users,
    )
    application.include_router(health.router)
    application.include_router(auth.router)
    application.include_router(users.router)
    application.include_router(blog.router)
    application.include_router(community.router)
    application.include_router(social.router)
    application.include_router(feed.router)
    application.include_router(messages.router)
    application.include_router(moderation.router)
    application.include_router(admin.router)

    _register_error_handlers(application)
    return application


def _register_error_handlers(application: FastAPI) -> None:
    """One place that decides what a user sees when something goes wrong.

    Nothing here leaks exception text for 5xx — see app/services/errors.py.
    """

    @application.exception_handler(404)
    async def not_found_handler(request: Request, exc):
        return errors.not_found_response(request)

    @application.exception_handler(401)
    async def unauthorized_handler(request: Request, exc):
        return errors.unauthorized_response(request)

    @application.exception_handler(403)
    async def forbidden_handler(request: Request, exc):
        return errors.forbidden_response(request, getattr(exc, "detail", None))

    @application.exception_handler(429)
    async def rate_limited_handler(request: Request, exc):
        retry_after = 60
        headers = getattr(exc, "headers", None) or {}
        try:
            retry_after = int(headers.get("Retry-After", retry_after))
        except (TypeError, ValueError):
            pass
        return errors.rate_limited_response(request, retry_after)

    @application.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc):
        # ServerErrorMiddleware re-raises after this response is sent, so the
        # traceback still reaches the server log — just not the browser.
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        return errors.server_error_response(request)


app = create_app()
