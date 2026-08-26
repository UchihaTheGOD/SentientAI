"""SentientAI — Main FastAPI application."""
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from starlette.middleware.base import BaseHTTPMiddleware
from app.database import init_db
from app.labs import init_labs


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
        return response


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    application = FastAPI(
        title="SentientAI",
        description="Cybersecurity Training Platform",
        version="0.1.0",
        docs_url="/api/docs",
        redoc_url=None,
    )

    # Middleware
    application.add_middleware(SecurityHeadersMiddleware)

    # Static files
    application.mount("/static", StaticFiles(directory="app/static"), name="static")

    # Register routers
    from app.api import auth, users, labs, attacks, admin, health
    application.include_router(health.router)
    application.include_router(auth.router)
    application.include_router(users.router)
    application.include_router(labs.router)
    application.include_router(attacks.router)
    application.include_router(admin.router)

    # Startup: init DB + labs
    @application.on_event("startup")
    def on_startup():
        init_db()
        init_labs()

    # Global 404 handler
    @application.exception_handler(404)
    async def not_found_handler(request: Request, exc):
        from fastapi.templating import Jinja2Templates
        templates = Jinja2Templates(directory="app/templates")
        return templates.TemplateResponse("404.html", {"request": request}, status_code=404)

    # Redirect unauthenticated requests to login
    from fastapi.exceptions import HTTPException as FastAPIHTTPException
    from fastapi.responses import RedirectResponse

    @application.exception_handler(401)
    async def unauthorized_handler(request: Request, exc):
        # API requests get JSON, browser requests get redirect
        if request.url.path.startswith("/api/"):
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "Not authenticated"}, status_code=401)
        return RedirectResponse(url="/login", status_code=303)

    return application


app = create_app()
