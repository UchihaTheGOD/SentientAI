"""Authentication and account security."""
from __future__ import annotations

from app.models.user import User
from tests.conftest import PASSWORD


def test_login_page_renders_for_anonymous(client):
    response = client.get("/login")
    assert response.status_code == 200
    assert "csrf_token" in response.text


def test_post_without_csrf_token_is_rejected(client, user):
    response = client.post(
        "/login", {"username": user.username, "password": PASSWORD}, csrf=False,
    )
    assert response.status_code == 403


def test_post_with_forged_csrf_token_is_rejected(client, user):
    response = client.post(
        "/login",
        {"username": user.username, "password": PASSWORD, "csrf_token": "forged.deadbeef"},
        csrf=False,
    )
    assert response.status_code == 403


def test_login_sets_httponly_cookie_and_lands_on_public_site(client, user):
    response = client.login(user.username)
    assert response.status_code == 303
    # Everyone lands on the public site — signing in is not a route into /testing.
    assert response.headers["location"] == "/"
    cookie_header = response.headers.get("set-cookie", "")
    assert "access_token=" in cookie_header
    assert "HttpOnly" in cookie_header or "httponly" in cookie_header


def test_wrong_password_is_indistinguishable_from_unknown_user(client, user):
    bad_password = client.post(
        "/login", {"username": user.username, "password": "WrongPassword123"},
    )
    unknown_user = client.post(
        "/login", {"username": "nobody-at-all", "password": "WrongPassword123"},
    )
    assert bad_password.status_code == unknown_user.status_code == 400
    assert "Incorrect username or password." in bad_password.text
    assert "Incorrect username or password." in unknown_user.text


def test_login_next_only_follows_local_paths(client, user):
    hijacked = client.login(user.username, next_url="https://evil.example/phish")
    assert hijacked.headers["location"] == "/"


def test_login_next_honours_a_local_path(client, user):
    response = client.login(user.username, next_url="/bookmarks")
    assert response.headers["location"] == "/bookmarks"


def test_suspended_account_cannot_sign_in(client, db, user):
    row = db.query(User).filter(User.id == user.id).first()
    row.is_suspended = True
    row.suspension_reason = "Testing suspension"
    db.commit()

    response = client.login(user.username)
    assert response.status_code == 400
    assert "suspended" in response.text.lower()


def test_registration_rejects_weak_password(client):
    response = client.post("/register", {
        "username": "weakling",
        "email": "weakling@example.test",
        "password": "alllowercase",
        "confirm_password": "alllowercase",
    })
    assert response.status_code == 400
    assert "uppercase" in response.text


def test_registration_creates_a_plain_user_not_an_admin(client, db):
    response = client.post("/register", {
        "username": "freshjoiner",
        "email": "freshjoiner@example.test",
        "password": PASSWORD,
        "confirm_password": PASSWORD,
    })
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login?registered=1")

    created = db.query(User).filter(User.username == "freshjoiner").first()
    assert created is not None
    # A request must never be able to grant itself a role.
    assert created.role == "user"
    assert created.password_hash != PASSWORD


def test_registration_cannot_choose_its_own_role(client, db):
    client.post("/register", {
        "username": "wannabeadmin",
        "email": "wannabeadmin@example.test",
        "password": PASSWORD,
        "confirm_password": PASSWORD,
        "role": "admin",
        "is_admin": "true",
    })
    created = db.query(User).filter(User.username == "wannabeadmin").first()
    assert created is not None and created.role == "user"


def test_password_page_requires_authentication(client):
    response = client.get("/account/password")
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login?next=/account/password")


def test_password_change_requires_the_current_password(auth_client):
    response = auth_client.post("/account/password", {
        "current_password": "NotMyPassword1",
        "new_password": "BrandNewPass1",
        "confirm_password": "BrandNewPass1",
    })
    assert response.status_code == 400
    assert "current password is incorrect" in response.text


def test_password_change_succeeds_and_old_password_stops_working(app, client, user):
    assert client.login(user.username).status_code == 303
    changed = client.post("/account/password", {
        "current_password": PASSWORD,
        "new_password": "BrandNewPass1",
        "confirm_password": "BrandNewPass1",
    })
    assert changed.status_code == 200

    client.logout()
    assert client.login(user.username, PASSWORD).status_code == 400
    assert client.login(user.username, "BrandNewPass1").status_code == 303


def test_logout_clears_the_session_cookie(auth_client):
    response = auth_client.logout()
    assert response.status_code == 303
    assert auth_client.get("/account/password").status_code == 303
