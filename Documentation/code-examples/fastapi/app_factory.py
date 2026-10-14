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