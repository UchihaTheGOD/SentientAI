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
        # <script> would not execute. All page scripts live in
        # app/static/js/ (no inline <script> or onclick handlers remain);
        # 'unsafe-inline' is kept only for style-src, where style
        # attributes are used throughout the templates.
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
    # Sentinel: schedule background warm-load so readiness reflects real state
    # without blocking startup (2-4s / ~1.9 GB). Kept inside lifespan so both
    # the initial boot and every reload (run.py reload_dirs=["app"]) trigger it.
    # The endpoint POST /api/sentinel/readiness/load remains the explicit sync path.
    # Fail-open: missing torch/tokenizers must never crash the app.
    try:
        from app.services.sentinel_loader import init_sentinel  # local import: loader pulls config/tokenizer lazily
        init_sentinel(background=True)
        logger.info("Sentinel background load scheduled")
    except Exception as exc:  # pragma: no cover — startup must not crash on model issues
        logger.warning("sentinel background init failed: %s", exc)
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
    # headers must wrap everything including CSRF rejections. SecurityEvents
    # is outermost so it sees correlation_id/duration for all inner responses.
    application.add_middleware(CSRFMiddleware)
    application.add_middleware(SecurityHeadersMiddleware)
    from app.middleware.security_events import SecurityEventsMiddleware
    application.add_middleware(SecurityEventsMiddleware)

    # Project-root-relative static dir: launching from another cwd must
    # not break /static (run.bat already cd's to its own folder, but the
    # Python entry point alone should not depend on that).
    from pathlib import Path as _Path

    application.mount(
        "/static",
        StaticFiles(directory=str(_Path(__file__).resolve().parent / "static")),
        name="static",
    )

    from app.api import (
        admin, auth, blog, community, feed, health, messages, moderation,
        sentinel, social, users,
        cyberllm,
    )
    from app.api.security import router as security_router
    from app.api.admin_security import router as admin_security_router
    from app.api.security_lab_api import router as lab_router
    from app.api.theme import router as theme_router
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
    application.include_router(sentinel.router)
    application.include_router(cyberllm.router)
    application.include_router(security_router)
    application.include_router(lab_router)
    application.include_router(admin_security_router)
    application.include_router(theme_router)
    # alias /admin/reports/security -> same handler as /admin/security/reports/security (Phase 2 nav)
    from fastapi import Depends as _Dep
    from fastapi import Request as _Req2
    from fastapi.responses import HTMLResponse as _HR2
    from sqlalchemy.orm import Session as _Sess2
    from app.database import get_db as _get_db2
    from app.services.auth_service import require_admin as _req_admin2
    from app.models.user import User as _User2
    from app.template_env import templates as _tmpl2
    from fastapi import APIRouter as _APIR2
    _reports_alias = _APIR2(prefix="/admin/reports", tags=["admin-security-alias"])
    @_reports_alias.get("/security", response_class=_HR2)
    def _alias_reports_security(request: _Req2, db: _Sess2 = _Dep(_get_db2), user: _User2 = _Dep(_req_admin2)):  # type: ignore
        return _tmpl2.TemplateResponse("admin_reports_security.html", {"request": request, "current_user": user, "user": user, "filters": {"test_type": "", "status": "", "severity": ""}})
    @_reports_alias.get("/security/{rid}", response_class=_HR2)
    def _alias_reports_security_detail(rid: int, request: _Req2, db: _Sess2 = _Dep(_get_db2), user: _User2 = _Dep(_req_admin2)):  # type: ignore
        from app.models.security_lab import SecurityLabRun as _RL
        from app.models.attact_assessment import SecurityEvent as _SE
        import json as _j
        run = db.query(_RL).filter(_RL.id == rid).first()
        if not run:
            from fastapi import HTTPException as _HE; raise _HE(status_code=404)
        try: eids=_j.loads(run.event_ids or "[]")
        except Exception: eids=[]
        events=[]
        if eids:
            rows=db.query(_SE).filter(_SE.id.in_(eids)).all()
            events=[{"id": x.id, "event_type": x.event_type, "category": x.category, "severity": x.severity, "source": x.source, "evidence": (x.evidence or "")[:1200], "correlation_id": x.correlation_id, "created_at": x.created_at} for x in rows]
        incident=None; candidate=None
        try:
            if getattr(run,"incident_id",None):
                from app.models.sentinel_incident import SentinelIncident as _SI
                incident=db.query(_SI).filter(_SI.id==run.incident_id).first()
        except Exception: pass
        try:
            if getattr(run,"training_candidate_id",None):
                from app.models.training_example import TrainingExample as _TE
                candidate=db.query(_TE).filter(_TE.id==run.training_candidate_id).first()
        except Exception: pass
        try: meta=_j.loads(run.meta_json or "{}")
        except Exception: meta={}
        try: fusion=_j.loads(run.fusion_json) if getattr(run,"fusion_json",None) else None
        except Exception: fusion=None
        return _tmpl2.TemplateResponse("admin_reports_security_detail.html", {"request": request, "current_user": user, "user": user, "run": run, "events": events, "incident": incident, "candidate": candidate, "meta": meta, "fusion": fusion})
    application.include_router(_reports_alias)

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
