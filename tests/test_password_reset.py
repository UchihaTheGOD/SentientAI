"""Password reset: forgot → emailed single-use link → set a new password.

The flow is a chain of security properties, so each test pins one of them:

* the "forgot" form cannot be used to tell whether an email is registered
  (no account enumeration): the response is byte-identical either way, and a
  token row is created only for a real, active account;
* only the SHA-256 *hash* of a token is ever stored — never the raw value, and
  never the raw value in the audit trail;
* a token is single-use and expiring; forged/expired/used tokens are rejected;
* a successful reset stores a new Argon2id hash, invalidates every existing
  session (token_version bump), and does NOT sign the user in;
* the state-changing endpoint is CSRF-protected.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.models.audit import AuditEvent
from app.models.password_reset import PasswordResetToken
from app.models.user import User
from app.services import password_reset as reset_service
from app.services.auth_service import verify_password

from tests.conftest import PASSWORD, Client

NEW_PASSWORD = "FreshPassw0rd"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _tokens_for(db, user_id: int):
    return (
        db.query(PasswordResetToken)
        .filter(PasswordResetToken.user_id == user_id)
        .all()
    )


def _access_cookie_values(response) -> list[str]:
    """The value of every `access_token` Set-Cookie on a response.

    A successful *login* sets this to a JWT; `delete_cookie` sets it empty. The
    discriminator between "logged in" and "not logged in" is exactly whether any
    of these values is non-empty.
    """
    values = []
    for raw in response.headers.get_list("set-cookie"):
        name, _, rest = raw.partition("=")
        if name.strip() == "access_token":
            values.append(rest.split(";", 1)[0].strip())
    return values


def _grants_session(response) -> bool:
    return any(v not in ("", '""') for v in _access_cookie_values(response))


# ---------------------------------------------------------------------------
# forgot-password form
# ---------------------------------------------------------------------------

def test_forgot_password_page_renders(client):
    resp = client.get("/forgot-password")
    assert resp.status_code == 200
    assert 'name="email"' in resp.text
    assert 'action="/forgot-password"' in resp.text


def test_forgot_with_unknown_email_creates_no_token(client, db):
    resp = client.post("/forgot-password", {"email": "nobody@nowhere.test"})
    assert resp.status_code == 200
    assert "If an account exists" in resp.text
    assert db.query(PasswordResetToken).count() == 0


def test_forgot_with_known_email_creates_one_single_use_token(client, db, user):
    resp = client.post("/forgot-password", {"email": user.email})
    assert resp.status_code == 200

    tokens = _tokens_for(db, user.id)
    assert len(tokens) == 1
    row = tokens[0]
    assert row.used_at is None
    assert not row.is_expired()
    # Stored value is a 64-char SHA-256 hex digest, not anything raw.
    assert len(row.token_hash) == 64
    int(row.token_hash, 16)  # raises if not hex


def test_forgot_response_is_identical_for_known_and_unknown(client, user):
    # No enumeration: the bytes returned must not depend on whether the address
    # matched an account. The "sent" branch renders no form and no per-request
    # token, so the two bodies are identical.
    known = client.post("/forgot-password", {"email": user.email})
    unknown = client.post("/forgot-password", {"email": "ghost@nowhere.test"})
    assert known.status_code == unknown.status_code == 200
    assert known.text == unknown.text


def test_only_the_token_hash_is_stored_never_the_raw(db, user):
    raw = reset_service.create_reset_token(db, user)
    row = _tokens_for(db, user.id)[0]
    assert row.token_hash == reset_service.hash_token(raw)
    assert row.token_hash != raw
    assert raw not in row.token_hash


def test_requesting_a_new_link_retires_the_old_one(db, user):
    first = reset_service.create_reset_token(db, user)
    second = reset_service.create_reset_token(db, user)
    # Both rows exist, but only the newest is usable.
    assert len(_tokens_for(db, user.id)) == 2
    assert reset_service.verify_token(db, first) is None
    assert reset_service.verify_token(db, second) is not None


# ---------------------------------------------------------------------------
# reset-password page (GET)
# ---------------------------------------------------------------------------

def test_reset_page_with_valid_token_shows_form(client, db, user):
    raw = reset_service.create_reset_token(db, user)
    resp = client.get(f"/reset-password?token={raw}")
    assert resp.status_code == 200
    assert 'name="new_password"' in resp.text
    assert raw in resp.text  # carried in the hidden field for the POST


def test_reset_page_with_bad_token_shows_invalid(client):
    resp = client.get("/reset-password?token=not-a-real-token")
    assert resp.status_code == 200
    assert "invalid or has expired" in resp.text
    assert 'name="new_password"' not in resp.text


# ---------------------------------------------------------------------------
# reset-password (POST) — the actual reset
# ---------------------------------------------------------------------------

def test_reset_sets_new_password_and_does_not_log_in(app, db, user):
    raw = reset_service.create_reset_token(db, user)

    resp = Client(app).post("/reset-password", {
        "token": raw,
        "new_password": NEW_PASSWORD,
        "confirm_password": NEW_PASSWORD,
    })
    # A reset ends at the login page — it never signs the user in.
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login?reset=1"
    assert not _grants_session(resp)

    db.expire_all()
    refreshed = db.query(User).filter(User.id == user.id).first()
    assert verify_password(NEW_PASSWORD, refreshed.password_hash)
    assert not verify_password(PASSWORD, refreshed.password_hash)

    # End to end: the new password works, the old one does not.
    assert Client(app).login(user.username, password=NEW_PASSWORD).status_code == 303
    assert Client(app).login(user.username, password=PASSWORD).status_code == 400


def test_a_reset_token_is_single_use(app, db, user):
    raw = reset_service.create_reset_token(db, user)

    first = Client(app).post("/reset-password", {
        "token": raw, "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD,
    })
    assert first.status_code == 303

    second = Client(app).post("/reset-password", {
        "token": raw, "new_password": "Different9Pass", "confirm_password": "Different9Pass",
    })
    assert second.status_code == 400
    assert "invalid or has expired" in second.text

    # The second attempt changed nothing.
    db.expire_all()
    refreshed = db.query(User).filter(User.id == user.id).first()
    assert verify_password(NEW_PASSWORD, refreshed.password_hash)


def test_an_expired_token_is_rejected(client, db, user):
    raw = reset_service.generate_raw_token()
    db.add(PasswordResetToken(
        user_id=user.id,
        token_hash=reset_service.hash_token(raw),
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    ))
    db.commit()

    assert reset_service.verify_token(db, raw) is None
    resp = client.post("/reset-password", {
        "token": raw, "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD,
    })
    assert resp.status_code == 400
    assert "invalid or has expired" in resp.text


def test_a_forged_token_is_rejected(client, db, user):
    resp = client.post("/reset-password", {
        "token": "totally-made-up",
        "new_password": NEW_PASSWORD,
        "confirm_password": NEW_PASSWORD,
    })
    assert resp.status_code == 400
    # A forged token must never touch a real account's password.
    db.expire_all()
    refreshed = db.query(User).filter(User.id == user.id).first()
    assert verify_password(PASSWORD, refreshed.password_hash)


def test_a_reset_invalidates_existing_sessions(auth_client, db, user):
    # The signed-in session works before the reset.
    assert auth_client.get("/account/password").status_code == 200

    raw = reset_service.create_reset_token(db, user)
    row = reset_service.verify_token(db, raw)
    reset_service.consume_reset(db, row, NEW_PASSWORD)

    # token_version was bumped, so the previously-valid cookie is now stale and
    # the protected page bounces to login.
    after = auth_client.get("/account/password")
    assert after.status_code in (302, 303, 401)


def test_weak_new_password_is_rejected(app, db, user):
    raw = reset_service.create_reset_token(db, user)
    resp = Client(app).post("/reset-password", {
        "token": raw, "new_password": "weak", "confirm_password": "weak",
    })
    assert resp.status_code == 400
    assert 'name="new_password"' in resp.text  # form re-shown, not the invalid page

    # A rejected attempt must not spend the token or change the password.
    assert reset_service.verify_token(db, raw) is not None
    db.expire_all()
    refreshed = db.query(User).filter(User.id == user.id).first()
    assert verify_password(PASSWORD, refreshed.password_hash)


def test_mismatched_confirmation_is_rejected(app, db, user):
    raw = reset_service.create_reset_token(db, user)
    resp = Client(app).post("/reset-password", {
        "token": raw,
        "new_password": NEW_PASSWORD,
        "confirm_password": "Different9Pass",
    })
    assert resp.status_code == 400
    assert reset_service.verify_token(db, raw) is not None  # token not spent


# ---------------------------------------------------------------------------
# audit + CSRF
# ---------------------------------------------------------------------------

def test_a_reset_records_an_audit_event_without_leaking_the_token(app, db, user):
    raw = reset_service.create_reset_token(db, user)
    Client(app).post("/reset-password", {
        "token": raw, "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD,
    })

    events = db.query(AuditEvent).filter(AuditEvent.event_type == "auth.password_reset").all()
    assert len(events) == 1
    # The raw token must never be written to the trail (nor anywhere else).
    for e in events:
        for field in (e.detail, e.actor_label, e.target_id):
            assert raw not in (field or "")


def test_reset_requires_csrf(app, db, user):
    raw = reset_service.create_reset_token(db, user)
    resp = Client(app).post(
        "/reset-password",
        {"token": raw, "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD},
        csrf=False,
    )
    assert resp.status_code == 403
    # The token survives a blocked request.
    assert reset_service.verify_token(db, raw) is not None
