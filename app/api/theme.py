"""Theme preference API — persistent for authenticated users, localStorage for anonymous.

Precedence:
 1. Explicit Light/Dark stored in User.theme_preference.
 2. System when theme_preference is NULL/'system' or no preference exists (media query).

Anonymous visitors use localStorage only; this API is auth-gated.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.services.auth_service import get_current_user, get_current_user_optional

router = APIRouter(prefix="/api/user", tags=["theme"])

VALID_THEMES = {"system", "light", "dark"}


class ThemeBody(BaseModel):
    theme: str

    model_config = {"extra": "forbid"}


@router.get("/theme")
def get_theme(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    raw = (getattr(user, "theme_preference", None) or "system").strip().lower()
    if raw not in VALID_THEMES:
        raw = "system"
    return {"theme": raw}


@router.post("/theme")
def set_theme(
    body: ThemeBody,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    raw = (body.theme or "").strip().lower()
    if raw not in VALID_THEMES:
        raise HTTPException(status_code=422, detail="Theme must be one of: system, light, dark")
    # Normalize: store NULL for system to keep legacy rows consistent
    user.theme_preference = None if raw == "system" else raw
    db.add(user)
    db.commit()
    return {"theme": raw}


@router.get("/theme-resolve")
def resolve_theme(
    request: Request,
    user=Depends(get_current_user_optional),
    db: Session = Depends(get_db),
):
    """Public resolve helper used by tests and inline fallback — returns server-known preference without auth requirement."""
    if user is None:
        return {"theme": "system", "authenticated": False}
    raw = (getattr(user, "theme_preference", None) or "system").strip().lower()
    if raw not in VALID_THEMES:
        raw = "system"
    return {"theme": raw, "authenticated": True}
