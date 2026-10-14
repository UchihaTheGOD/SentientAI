"""Password-reset flow: token issuance, verification, and delivery.

Security properties this module is responsible for:

* **Tokens are random and opaque.** ``secrets.token_urlsafe`` gives ~256 bits of
  entropy; the raw value is returned once (to be emailed) and never stored — only
  its SHA-256 hash is persisted, so a database leak cannot mint a valid link.
* **Single-use and short-lived.** Issuing a new token retires the account's
  earlier ones, and every token carries an ``expires_at``.
* **No enumeration.** ``initiate_reset`` does the same thing whether or not the
  email matches an account, and it never signals which. The caller always shows
  the same generic confirmation.
* **Nothing sensitive is logged.** The raw token is written only into the email
  body. When SMTP is unconfigured the link is logged *only* outside production,
  as a developer convenience.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Callable, Optional

from sqlalchemy.orm import Session

from app.config import settings
from app.models.password_reset import PasswordResetToken
from app.models.user import User
from app.services.auth_service import hash_password

logger = logging.getLogger("sentientai.password_reset")

# 32 bytes → a ~43-char URL-safe string. Comfortably beyond guessing.
_TOKEN_BYTES = 32


# ---------------------------------------------------------------------------
# Token primitives
# ---------------------------------------------------------------------------

def generate_raw_token() -> str:
    return secrets.token_urlsafe(_TOKEN_BYTES)


def hash_token(raw: str) -> str:
    """Deterministic SHA-256 hex used both to store and to look a token up.

    A plain hash (not Argon2) is correct here: the token is already
    high-entropy, so there is nothing to brute-force, and lookup must be by
    exact value.
    """
    return hashlib.sha256((raw or "").encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Issue / verify / consume
# ---------------------------------------------------------------------------

def _retire_active_tokens(db: Session, user_id: int) -> None:
    """Mark every still-unused token for this account as spent.

    Requesting a new link should invalidate any older one, so a forwarded or
    intercepted earlier email stops working the moment the user tries again.
    """
    now = _now()
    (
        db.query(PasswordResetToken)
        .filter(
            PasswordResetToken.user_id == user_id,
            PasswordResetToken.used_at.is_(None),
        )
        .update({PasswordResetToken.used_at: now}, synchronize_session=False)
    )


def create_reset_token(db: Session, user: User) -> str:
    """Issue a fresh token for ``user`` and return the RAW value (emailed once)."""
    _retire_active_tokens(db, user.id)
    raw = generate_raw_token()
    row = PasswordResetToken(
        user_id=user.id,
        token_hash=hash_token(raw),
        expires_at=_now() + timedelta(minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES),
    )
    db.add(row)
    db.commit()
    return raw


def verify_token(db: Session, raw: str) -> Optional[PasswordResetToken]:
    """Return the token row iff it exists, is unused, and has not expired."""
    if not raw:
        return None
    row = (
        db.query(PasswordResetToken)
        .filter(PasswordResetToken.token_hash == hash_token(raw))
        .first()
    )
    if row is None or not row.is_valid():
        return None
    return row


def consume_reset(db: Session, token_row: PasswordResetToken, new_password: str) -> User:
    """Apply a verified reset: set the new hash, kill sessions, spend the token.

    Every step is one transaction:
      * store only the new Argon2id hash (plaintext is never persisted);
      * bump ``token_version`` so all existing sessions on every device die;
      * mark this token used and retire any siblings.
    The caller must NOT sign the user in — a reset ends at the login page.
    """
    user = db.query(User).filter(User.id == token_row.user_id).first()
    if user is None:
        raise ValueError("Token references a missing user.")

    user.password_hash = hash_password(new_password)
    user.token_version = (user.token_version or 0) + 1

    token_row.used_at = _now()
    _retire_active_tokens(db, user.id)  # any parallel outstanding tokens
    db.commit()
    db.refresh(user)
    return user


# ---------------------------------------------------------------------------
# Delivery
# ---------------------------------------------------------------------------

def _email_body(reset_url: str) -> str:
    minutes = settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES
    return (
        "Someone (hopefully you) asked to reset the password on your Sentient "
        "account.\n\n"
        f"Reset it here:\n{reset_url}\n\n"
        f"This link can be used once and expires in {minutes} minutes. "
        "If you didn't request this, you can safely ignore this email — your "
        "password will not change.\n"
    )


def send_reset_email(to_addr: str, reset_url: str) -> bool:
    """Send the reset link over SMTP (STARTTLS). Returns whether it was sent.

    A blank ``SMTP_HOST`` means email is not configured: outside production the
    link is logged for local testing; in production that is an error and no link
    is ever logged.
    """
    body = _email_body(reset_url)
    if not settings.SMTP_HOST:
        if settings.is_production:
            logger.error("SMTP is not configured; password-reset email not sent.")
        else:
            logger.warning("SMTP not configured (dev). Reset email would say:\n%s", body)
        return False

    message = EmailMessage()
    message["Subject"] = "Reset your Sentient password"
    message["From"] = settings.SMTP_FROM or settings.SMTP_USERNAME
    message["To"] = to_addr
    message.set_content(body)

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as smtp:
            if settings.SMTP_USE_TLS:
                smtp.starttls()
            if settings.SMTP_USERNAME:
                smtp.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            smtp.send_message(message)
        return True
    except Exception:
        # Never surface delivery failure to the requester (that would leak that
        # the address exists); log it for the operator instead.
        logger.exception("Failed to send password-reset email.")
        return False


# ---------------------------------------------------------------------------
# Enumeration-safe entry point used by the route
# ---------------------------------------------------------------------------

def initiate_reset(db: Session, *, email: str, build_url: Callable[[str], str]) -> None:
    """Best-effort: if the email maps to an account, issue and send a link.

    Returns nothing and raises nothing the caller can branch on — the route
    shows an identical message either way, so the form cannot reveal whether an
    address is registered. ``build_url`` turns a raw token into the absolute
    reset URL (the route builds it from the request).
    """
    address = (email or "").strip().lower()
    if not address:
        return
    user = db.query(User).filter(User.email == address).first()
    if user is None or not user.is_active:
        # No account, or a deactivated one: send nothing. The generic response
        # the route returns is what keeps this from revealing the difference.
        return
    raw = create_reset_token(db, user)
    send_reset_email(user.email, build_url(raw))
