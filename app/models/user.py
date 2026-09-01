"""User model."""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="user", nullable=False, index=True)  # user | admin
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Bumped to invalidate every existing session at once — on logout, password
    # change/reset, suspension, deletion, and admin reset. Tokens carry the value
    # they were minted with; a mismatch in get_current_user means it is stale.
    token_version = Column(Integer, default=0, nullable=False)

    # Profile fields (nullable — existing rows get NULL, filled via /profile edit)
    display_name = Column(String(100), nullable=True)
    bio = Column(Text, nullable=True)
    website = Column(String(255), nullable=True)
    avatar_url = Column(String(500), nullable=True)

    # Moderation (admin-only, see app/api/moderation.py). Kept separate from
    # `is_active` so an account can be deactivated for other reasons.
    is_suspended = Column(Boolean, default=False, nullable=False, index=True)
    suspension_reason = Column(String(255), nullable=True)
    suspended_at = Column(DateTime, nullable=True)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def can_sign_in(self) -> bool:
        return bool(self.is_active) and not bool(self.is_suspended)

    @property
    def display(self) -> str:
        """User-facing name: display_name if set, else username."""
        return self.display_name or self.username

