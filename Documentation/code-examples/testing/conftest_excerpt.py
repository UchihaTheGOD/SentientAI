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