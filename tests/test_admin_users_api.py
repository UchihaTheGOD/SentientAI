"""Tests for the admin user-management JSON API (Security Lab).

Covers the acceptance criteria: admins can act, ordinary users get
403, role changes take effect, self-removal and last-admin removal
are refused, duplicates are rejected, and no secret ever appears in
a response.
"""

from __future__ import annotations


def _patch(client, url, payload):
    return client._client.patch(
        url, json=payload,
        headers={"X-CSRF-Token": client._csrf()})


def _post_json(client, url, payload):
    return client._client.post(
        url, json=payload,
        headers={"X-CSRF-Token": client._csrf()})


def _admin_ids(client):
    resp = client.get("/api/admin/users?per_page=100")
    assert resp.status_code == 200
    return [u["id"] for u in resp.json()["users"]
            if u["role"] == "admin"]


def test_admin_can_list_users(admin_client, user):
    resp = admin_client.get("/api/admin/users")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert data["admins"] >= 1
    usernames = [u["username"] for u in data["users"]]
    assert user.username in usernames
    assert "password_hash" not in resp.text
    assert "token_version" not in resp.text
    for entry in data["users"]:
        assert set(entry) <= {
            "id", "username", "email", "role", "is_active", "is_suspended",
            "suspension_reason", "display_name", "created_at", "can_sign_in",
        }


def test_user_cannot_list_users(auth_client):
    assert auth_client.get("/api/admin/users").status_code == 403


def test_anonymous_cannot_list_users(client):
    assert client.get("/api/admin/users").status_code == 401


def test_admin_can_view_user_detail(admin_client, user):
    resp = admin_client.get(f"/api/admin/users/{user.id}")
    assert resp.status_code == 200
    assert resp.json()["user"]["username"] == user.username
    assert "password_hash" not in resp.text


def test_user_cannot_view_user_detail(auth_client, user):
    assert auth_client.get(f"/api/admin/users/{user.id}").status_code == 403


def test_role_change_takes_effect(admin_client, user):
    resp = _patch(admin_client, f"/api/admin/users/{user.id}/role",
                  {"role": "admin"})
    assert resp.status_code == 200
    assert resp.json()["role"] == "admin"
    detail = admin_client.get(f"/api/admin/users/{user.id}")
    assert detail.json()["user"]["role"] == "admin"
    resp = _patch(admin_client, f"/api/admin/users/{user.id}/role",
                  {"role": "user"})
    assert resp.status_code == 200
    assert resp.json()["role"] == "user"


def test_invalid_role_rejected(admin_client, user):
    resp = _patch(admin_client, f"/api/admin/users/{user.id}/role",
                  {"role": "superuser"})
    assert resp.status_code == 400


def test_self_role_change_refused(admin_client, admin):
    resp = _patch(admin_client, f"/api/admin/users/{admin.id}/role",
                  {"role": "user"})
    assert resp.status_code == 400


def test_self_deactivation_and_suspension_refused(admin_client, admin):
    assert _patch(admin_client, f"/api/admin/users/{admin.id}/active",
                  {"is_active": False}).status_code == 400
    assert _patch(admin_client, f"/api/admin/users/{admin.id}/suspend",
                  {"is_suspended": True}).status_code == 400


def test_demote_to_one_admin_then_self_refused(admin_client, admin):
    # Demote every other admin: each demotion succeeds while at least
    # two active admins remain, leaving exactly one (the actor).
    for other_id in _admin_ids(admin_client):
        if other_id != admin.id:
            resp = _patch(admin_client, f"/api/admin/users/{other_id}/role",
                          {"role": "user"})
            assert resp.status_code == 200, resp.text
    assert _admin_ids(admin_client) == [admin.id]
    # The last admin cannot remove themselves.
    assert _patch(admin_client, f"/api/admin/users/{admin.id}/role",
                  {"role": "user"}).status_code == 400


def test_deactivate_and_reactivate(admin_client, user):
    resp = _patch(admin_client, f"/api/admin/users/{user.id}/active",
                  {"is_active": False})
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False
    assert resp.json()["can_sign_in"] is False
    resp = _patch(admin_client, f"/api/admin/users/{user.id}/active",
                  {"is_active": True})
    assert resp.status_code == 200
    assert resp.json()["is_active"] is True


def test_suspend_and_unsuspend(admin_client, user):
    resp = _patch(admin_client, f"/api/admin/users/{user.id}/suspend",
                  {"is_suspended": True, "reason": "test suspension"})
    assert resp.status_code == 200
    assert resp.json()["is_suspended"] is True
    assert resp.json()["suspension_reason"] == "test suspension"
    assert resp.json()["can_sign_in"] is False
    resp = _patch(admin_client, f"/api/admin/users/{user.id}/suspend",
                  {"is_suspended": False})
    assert resp.status_code == 200
    assert resp.json()["is_suspended"] is False
    assert resp.json()["suspension_reason"] is None


def test_create_user_and_duplicates(admin_client):
    payload = {"username": "labcreated1", "email": "labcreated1@example.test",
               "password": "StrongPass1", "role": "user"}
    resp = _post_json(admin_client, "/api/admin/users", payload)
    assert resp.status_code == 201, resp.text
    assert resp.json()["username"] == "labcreated1"
    assert "StrongPass1" not in resp.text
    assert "password_hash" not in resp.text
    dup_name = _post_json(admin_client, "/api/admin/users",
                          {**payload, "email": "other@example.test"})
    assert dup_name.status_code == 409
    dup_email = _post_json(admin_client, "/api/admin/users",
                           {**payload, "username": "labcreated2"})
    assert dup_email.status_code == 409


def test_create_validation(admin_client):
    base = {"username": "okuser9", "email": "okuser9@example.test",
            "password": "StrongPass1", "role": "user"}
    assert _post_json(admin_client, "/api/admin/users",
                      {**base, "username": "ab"}).status_code == 400
    assert _post_json(admin_client, "/api/admin/users",
                      {**base, "username": "bad name!"}).status_code == 400
    assert _post_json(admin_client, "/api/admin/users",
                      {**base, "password": "weak"}).status_code == 400
    assert _post_json(admin_client, "/api/admin/users",
                      {**base, "role": "root"}).status_code == 400


def test_user_cannot_create_or_change_roles(auth_client, user):
    assert _post_json(auth_client, "/api/admin/users",
                      {"username": "nope1", "email": "nope1@example.test",
                       "password": "StrongPass1"}).status_code == 403
    assert _patch(auth_client, f"/api/admin/users/{user.id}/role",
                  {"role": "admin"}).status_code == 403


def test_password_reset_initiated(admin_client, user):
    resp = _post_json(admin_client,
                      f"/api/admin/users/{user.id}/password-reset", {})
    assert resp.status_code == 200, resp.text
    assert "token=" not in resp.text
    events = admin_client.get(
        "/api/admin/audit-events?event_type=admin.password_reset_initiated"
    )
    assert events.status_code == 200
    assert any(e["target_id"] == str(user.id)
               for e in events.json()["events"])


def test_role_change_is_audited(admin_client, user):
    _patch(admin_client, f"/api/admin/users/{user.id}/role",
           {"role": "admin"})
    events = admin_client.get(
        "/api/admin/audit-events?event_type=admin.user_role_changed")
    assert events.status_code == 200
    assert any(e["target_id"] == str(user.id)
               for e in events.json()["events"])


def test_audit_events_forbidden_for_users(auth_client):
    assert auth_client.get("/api/admin/audit-events").status_code == 403


def test_missing_user_404(admin_client):
    assert admin_client.get("/api/admin/users/999999").status_code == 404
    assert _patch(admin_client, "/api/admin/users/999999/role",
                  {"role": "admin"}).status_code == 404
