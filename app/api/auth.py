"""Authentication routes — register, login, logout, password change."""
import re
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.services import audit
from app.services.activity_service import log_activity
from app.services.auth_service import (
    create_access_token, get_current_user, get_current_user_optional,
    hash_password, verify_password,
)
from app.services.ratelimit import limit_login, limit_password, limit_register
from app.template_env import templates

router = APIRouter(tags=["auth"])


def _validate_registration(username: str, email: str, password: str, confirm_password: str):
    """Returns error message string or None if valid."""
    if not username or len(username) < 3 or len(username) > 50:
        return "Username must be 3-50 characters."
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return "Username can only contain letters, numbers, and underscores."
    if not email or not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        return "Invalid email address."
    error = _validate_password(password)
    if error:
        return error
    if password != confirm_password:
        return "Passwords do not match."
    return None


def _validate_password(password: str):
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if len(password) > 200:
        return "Password must be under 200 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one number."
    return None


def safe_next(raw: str | None) -> str:
    """Only ever redirect to a path on this site.

    An open redirect here would let a phishing link bounce through our login
    page, so anything with a scheme, host, or backslash is discarded.
    """
    if not raw:
        return "/"
    candidate = raw.strip()
    if not candidate.startswith("/") or candidate.startswith(("//", "/\\")):
        return "/"
    parts = urlsplit(candidate)
    if parts.scheme or parts.netloc:
        return "/"
    target = parts.path or "/"
    if parts.query:
        target = f"{target}?{parts.query}"
    return target[:500]


@router.get("/register", response_class=HTMLResponse)
def register_page(
    request: Request,
    next: str = Query(""),
    user=Depends(get_current_user_optional),
):
    if user:
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse("register.html", {
        "request": request, "error": None, "next": safe_next(next),
    })


@router.post("/register", response_class=HTMLResponse,
             dependencies=[Depends(limit_register)])
def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    next: str = Form(""),
    db: Session = Depends(get_db),
):
    username = username.strip()
    email = email.strip().lower()

    def fail(message: str):
        return templates.TemplateResponse("register.html", {
            "request": request, "error": message,
            "username": username, "email": email, "next": safe_next(next),
        }, status_code=400)

    error = _validate_registration(username, email, password, confirm_password)
    if error:
        return fail(error)

    if db.query(User).filter(User.username == username).first():
        return fail("That username is already taken.")
    if db.query(User).filter(User.email == email).first():
        return fail("An account with that email already exists.")

    # All new registrations are normal users. Role promotion is a CLI action
    # (manage.py) — never something a request can grant itself.
    user = User(
        username=username,
        email=email,
        hashed_password=hash_password(password),
        role="user",
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    log_activity(db, user.id, "account_created", "Joined Sentient", is_public=True)
    audit.record(db, "auth.register", user=user, request=request)
    audit.bump_metric(db, "registrations")

    target = safe_next(next)
    suffix = f"&next={target}" if target != "/" else ""
    return RedirectResponse(url=f"/login?registered=1{suffix}", status_code=303)


@router.get("/login", response_class=HTMLResponse)
def login_page(
    request: Request,
    registered: str = Query(""),
    next: str = Query(""),
    user=Depends(get_current_user_optional),
):
    if user:
        return RedirectResponse(url=safe_next(next), status_code=303)
    msg = "Account created — sign in to get started." if registered else None
    return templates.TemplateResponse("login.html", {
        "request": request, "error": None, "message": msg, "next": safe_next(next),
    })


@router.post("/login", response_class=HTMLResponse,
             dependencies=[Depends(limit_login)])
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: str = Form(""),
    db: Session = Depends(get_db),
):
    username = username.strip()
    target = safe_next(next)

    def fail(message: str):
        return templates.TemplateResponse("login.html", {
            "request": request, "error": message, "message": None,
            "username": username, "next": target,
        }, status_code=400)

    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        # Deliberately identical message for "no such user" and "wrong password"
        # so the form cannot be used to enumerate accounts.
        audit.record(db, "auth.login_failed", detail=f"username={username[:50]}", request=request)
        return fail("Incorrect username or password.")

    if not user.is_active:
        return fail("This account is deactivated.")
    if user.is_suspended:
        reason = f" Reason: {user.suspension_reason}" if user.suspension_reason else ""
        return fail(f"This account has been suspended.{reason}")

    token = create_access_token(data={"sub": str(user.id)})
    # Everyone lands on the public site. The testing area is reached
    # deliberately, never as a side effect of signing in.
    response = RedirectResponse(url=target, status_code=303)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.ENVIRONMENT == "production",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    audit.record(db, "auth.login", user=user, request=request)
    audit.bump_metric(db, "logins")
    return response


@router.post("/logout")
@router.get("/logout")
def logout(request: Request, db: Session = Depends(get_db),
           user=Depends(get_current_user_optional)):
    if user:
        audit.record(db, "auth.logout", user=user, request=request)
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("access_token")
    return response


# ---------------------------------------------------------------------------
# Password change
# ---------------------------------------------------------------------------

@router.get("/account/password", response_class=HTMLResponse)
def password_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse("account_password.html", {
        "request": request, "current_user": user, "errors": [], "success": False,
    })


@router.post("/account/password", response_class=HTMLResponse,
             dependencies=[Depends(limit_password)])
def password_change(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    errors = []
    if not verify_password(current_password, user.hashed_password):
        errors.append("Your current password is incorrect.")
    else:
        problem = _validate_password(new_password)
        if problem:
            errors.append(problem)
        elif new_password != confirm_password:
            errors.append("The new passwords do not match.")
        elif verify_password(new_password, user.hashed_password):
            errors.append("The new password must be different from the current one.")

    if errors:
        return templates.TemplateResponse("account_password.html", {
            "request": request, "current_user": user, "errors": errors, "success": False,
        }, status_code=400)

    user.hashed_password = hash_password(new_password)
    db.commit()
    audit.record(db, "auth.password_changed", user=user, request=request)

    return templates.TemplateResponse("account_password.html", {
        "request": request, "current_user": user, "errors": [], "success": True,
    })
