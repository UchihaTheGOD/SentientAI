"""CSRF middleware regression tests.

The rest of the suite posts its CSRF token in the ``X-CSRF-Token`` header, which
takes an early return in ``CSRFMiddleware`` and never touches the request body.
A real browser submits the token in a hidden ``csrf_token`` *field* instead, and
that path makes the middleware read ``request.form()`` before the endpoint does.

Under Starlette's ``BaseHTTPMiddleware`` that read consumes the receive stream
unless the body is buffered first, so the endpoint would parse an empty body and
return 422 — every HTML form on the site broken, while this suite stayed green.
These tests pin the field path: the token must be *accepted* there, and a
missing or forged one must still be *rejected*.
"""
from __future__ import annotations

from app.models.user import User
from tests.conftest import Client


def test_a_browser_form_post_with_the_token_in_a_field_succeeds(client, db):
    """Register through the form field, not the header — the real browser path."""
    response = client.post_form("/register", {
        "username": "fielduser",
        "email": "fielduser@example.test",
        "password": "FieldPass123",
        "confirm_password": "FieldPass123",
    })
    # 303 on success; the bug turned this into 422 (endpoint saw an empty body).
    assert response.status_code == 303, response.text[:300]
    assert response.headers["location"] == "/login?registered=1"
    assert db.query(User).filter(User.username == "fielduser").first() is not None


def test_login_via_form_field_authenticates(client, user):
    response = client.post_form("/login", {
        "username": user.username,
        "password": "TestPassword123",
    })
    assert response.status_code == 303, response.text[:300]
    # A follow-up authenticated page is reachable, so the cookie really was set.
    assert client.get("/dashboard").status_code == 200


def test_a_form_post_without_any_token_is_rejected(client):
    response = client.post_form("/register", {
        "username": "notoken",
        "email": "notoken@example.test",
        "password": "FieldPass123",
        "confirm_password": "FieldPass123",
    }, csrf=False)
    assert response.status_code == 403


def test_a_form_post_with_a_forged_token_is_rejected(client):
    response = client.post_form("/register", {
        "csrf_token": "forged.deadbeefdeadbeefdeadbeefdeadbeef",
        "username": "forged",
        "email": "forged@example.test",
        "password": "FieldPass123",
        "confirm_password": "FieldPass123",
    }, csrf=False)
    assert response.status_code == 403


def test_the_header_path_still_works(client, db):
    """The X-CSRF-Token header branch must keep working alongside the fix."""
    response = client.post("/register", {
        "username": "headeruser",
        "email": "headeruser@example.test",
        "password": "FieldPass123",
        "confirm_password": "FieldPass123",
    })
    assert response.status_code == 303, response.text[:300]
    assert db.query(User).filter(User.username == "headeruser").first() is not None
