"""Password-reset token model.

A reset link carries a high-entropy random token. Only the SHA-256 *hash* of
that token is stored here — the raw value exists solely inside the emailed link,
so a leaked database cannot be used to reset anyone's password. Each row is
single-use (`used_at`) and short-lived (`expires_at`); see
app/services/password_reset.py for the lifecycle.
"""
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String

from app.database import Base


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    # SHA-256 hex of the raw token (64 chars). The raw token is never stored.
    token_hash = Column(String(64), unique=True, nullable=False, index=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=False)
    # Set the moment the token is spent. A non-null value means "already used".
    used_at = Column(DateTime, nullable=True)

    # -- helpers -----------------------------------------------------------
    @property
    def is_used(self) -> bool:
        return self.used_at is not None

    def is_expired(self, now: datetime | None = None) -> bool:
        moment = now or datetime.now(timezone.utc)
        expires = self.expires_at
        # Rows read back from SQLite are naive; compare on the same footing.
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires is None or moment >= expires

    def is_valid(self, now: datetime | None = None) -> bool:
        """Usable exactly once, before it expires."""
        return not self.is_used and not self.is_expired(now)
