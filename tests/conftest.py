"""Shared test fixtures.

Two things make these tests real rather than decorative:

* the app runs against a throwaway SQLite file, created fresh for the session,
  so nothing here can touch `data/sentientai.db`;
* the client posts a genuine CSRF token, because `CSRFMiddleware` is live in
  the app under test. A helper reads the token from the cookie the middleware
  sets on any GET and echoes it back in the `X-CSRF-Token` header, which is the
  same double-submit check the HTML forms satisfy via `csrf_input()`.

`DATABASE_URL` must be set before `app.database` is imported, since the engine
is created at module import time.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

_TMP_DIR = Path(tempfile.mkdtemp(prefix="sentientai-tests-"))
_DB_PATH = _TMP_DIR / "test.db"

os.environ["DATABASE_URL"] = f"sqlite:///{_DB_PATH.as_posix()}"
os.environ["SECRET_KEY"] = "test-secret-key-not-used-anywhere-else"
os.environ["ENVIRONMENT"] = "test"

from starlette.testclient import TestClient  # noqa: E402

from app.database import Base, SessionLocal, engine, init_db  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models.user import User  # noqa: E402
from app.services import ratelimit  # noqa: E402
from app.services.auth_service import hash_password  # noqa: E402

PASSWORD = "TestPassword123"


@pytest.fixture(scope="session", autouse=True)
def _schema():
    init_db()
    yield


@pytest.fixture(autouse=True)
def _clean_database():
    """Empty every table before each test.

    The schema is created once for the session, so without this the rows one
    test writes are still there for the next one — which shows up as unique-slug
    collisions and, worse, as counting assertions that pass or fail depending on
    test order. Deleting in reverse dependency order keeps foreign keys happy.
    """
    with engine.begin() as connection:
        for table in reversed(Base.metadata.sorted_tables):
            connection.execute(table.delete())
    yield


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    """Limits are process-global; without this, test order would decide
    whether a later test gets a 429."""
    ratelimit.reset()
    yield
    ratelimit.reset()


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


class Client:
    """TestClient wrapper that supplies the CSRF token on unsafe methods."""

    def __init__(self, app):
        self._client = TestClient(app, follow_redirects=False)
        # Any safe request makes the middleware issue the cookie.
        self._client.get("/")

    # -- plumbing ----------------------------------------------------------
    @property
    def cookies(self):
        return self._client.cookies

    def _csrf(self) -> str:
        token = self._client.cookies.get("csrf_token")
        if not token:
            self._client.get("/")
            token = self._client.cookies.get("csrf_token")
        return token or ""

    def get(self, url, **kwargs):
        return self._client.get(url, **kwargs)

    def post(self, url, data=None, *, csrf: bool = True, **kwargs):
        headers = dict(kwargs.pop("headers", {}) or {})
        if csrf:
            headers.setdefault("X-CSRF-Token", self._csrf())
        return self._client.post(url, data=data or {}, headers=headers, **kwargs)

    def post_form(self, url, data=None, *, csrf: bool = True, **kwargs):
        """POST the way a real browser does: the CSRF token rides in a hidden
        form *field*, not the X-CSRF-Token header.

        This exercises a different branch of CSRFMiddleware than post() — the one
        that has to read request.form() without eating the body the endpoint
        still needs. Regression cover for exactly that.
        """
        payload = dict(data or {})
        if csrf:
            payload.setdefault("csrf_token", self._csrf())
        return self._client.post(url, data=payload, **kwargs)

    # -- convenience -------------------------------------------------------
    def login(self, username: str, password: str = PASSWORD, next_url: str = ""):
        payload = {"username": username, "password": password}
        if next_url:
            payload["next"] = next_url
        return self.post("/login", payload)

    def logout(self):
        return self.get("/logout")

    def follow(self, response):
        """GET a redirect's target, so a flow can be asserted end to end."""
        location = response.headers.get("location")
        assert location, "response has no Location header"
        return self.get(location)


@pytest.fixture(scope="session")
def app():
    return create_app()


@pytest.fixture
def client(app):
    return Client(app)


# ---------------------------------------------------------------------------
# Accounts. Created directly in the database so a test does not depend on the
# registration form working, and each test gets its own usernames.
# ---------------------------------------------------------------------------

_counter = {"n": 0}


def _make_user(role: str = "user", **overrides) -> User:
    _counter["n"] += 1
    n = _counter["n"]
    session = SessionLocal()
    try:
        hashed = hash_password(PASSWORD)
        user = User(
            username=overrides.pop("username", f"{role}{n}"),
            email=overrides.pop("email", f"{role}{n}@example.test"),
            password_hash=hashed,
            role=role,
            **overrides,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        session.expunge(user)
        return user
    finally:
        session.close()


@pytest.fixture
def user():
    return _make_user("user")


@pytest.fixture
def other_user():
    return _make_user("user")


@pytest.fixture
def admin():
    return _make_user("admin")


@pytest.fixture
def auth_client(client, user):
    response = client.login(user.username)
    assert response.status_code == 303, response.text[:400]
    return client


@pytest.fixture
def other_client(app, other_user):
    """A signed-in client for the second account.

    Shared rather than per-module because "one account cannot see another's
    data" is the shape of most authorization tests here, and a second client
    has to be built on its own `Client` so the two cookie jars stay separate.
    """
    c = Client(app)
    response = c.login(other_user.username)
    assert response.status_code == 303, response.text[:400]
    return c


@pytest.fixture
def admin_client(app, admin):
    c = Client(app)
    response = c.login(admin.username)
    assert response.status_code == 303, response.text[:400]
    return c
