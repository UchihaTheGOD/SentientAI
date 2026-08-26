"""Authentication routes — register, login, logout."""
import re
from fastapi import APIRouter, Depends, Request, Form
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.services.auth_service import (
    hash_password, verify_password, create_access_token,
    get_current_user_optional,
)
from app.config import settings

router = APIRouter(tags=["auth"])
templates = Jinja2Templates(directory="app/templates")


def _validate_registration(username: str, email: str, password: str, confirm_password: str):
    """Returns error message string or None if valid."""
    if not username or len(username) < 3 or len(username) > 50:
        return "Username must be 3-50 characters."
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return "Username can only contain letters, numbers, and underscores."
    if not email or not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        return "Invalid email address."
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return "Password must contain at least one number."
    if password != confirm_password:
        return "Passwords do not match."
    return None


@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request, user=Depends(get_current_user_optional)):
    if user:
        return RedirectResponse(url="/dashboard", status_code=303)
    return templates.TemplateResponse("register.html", {"request": request, "error": None})


@router.post("/register", response_class=HTMLResponse)
def register(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    admin_secret: str = Form(""),
    db: Session = Depends(get_db),
):
    error = _validate_registration(username, email, password, confirm_password)
    if error:
        return templates.TemplateResponse("register.html", {"request": request, "error": error})

    # Check uniqueness
    if db.query(User).filter(User.username == username).first():
        return templates.TemplateResponse("register.html", {"request": request, "error": "Username already taken."})
    if db.query(User).filter(User.email == email).first():
        return templates.TemplateResponse("register.html", {"request": request, "error": "Email already registered."})

    # Create user
    is_admin = bool(admin_secret and admin_secret == settings.ADMIN_SECRET)
    user = User(
        username=username,
        email=email,
        hashed_password=hash_password(password),
        is_admin=is_admin,
    )
    db.add(user)
    db.commit()

    return RedirectResponse(url="/login?registered=1", status_code=303)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, registered: str = "", user=Depends(get_current_user_optional)):
    if user:
        return RedirectResponse(url="/dashboard", status_code=303)
    msg = "Account created. Please log in." if registered else None
    return templates.TemplateResponse("login.html", {"request": request, "error": None, "message": msg})


@router.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        return templates.TemplateResponse("login.html", {
            "request": request, "error": "Invalid username or password.", "message": None,
        })

    if not user.is_active:
        return templates.TemplateResponse("login.html", {
            "request": request, "error": "Account is deactivated.", "message": None,
        })

    token = create_access_token(data={"sub": str(user.id)})
    response = RedirectResponse(url="/dashboard", status_code=303)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return response


@router.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token")
    return response
