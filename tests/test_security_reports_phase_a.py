"""Security Reports GUI — authz + empty + save/retrieve + filters."""
from __future__ import annotations

def _admin_client(app, admin):
    from tests.conftest import Client
    c = Client(app); c.login(admin.username); return c

def _user_client(app, user):
    from tests.conftest import Client
    c = Client(app); c.login(user.username); return c

def test_admin_can_open_reports_page(app, admin):
    c = _admin_client(app, admin)
    r = c._client.get("/admin/reports/security", headers={"X-CSRF-Token": c._csrf()})
    assert r.status_code == 200
    assert "Security Reports" in r.text

def test_non_admin_cannot_access_reports(app, user):
    c = _user_client(app, user)
    r = c._client.get("/admin/reports/security", headers={"X-CSRF-Token": c._csrf()})
    assert r.status_code in (403, 401, 302, 404)

def test_anon_cannot_access_reports_api(app):
    from tests.conftest import Client
    from app.main import create_app
    anon = Client(create_app())
    r = anon._client.get("/api/security/lab/runs", headers={"X-CSRF-Token": anon._csrf()})
    assert r.status_code in (401, 403)

def test_empty_history_returns_items_empty(app, admin):
    c = _admin_client(app, admin)
    r = c._client.get("/api/security/lab/runs?limit=50", headers={"X-CSRF-Token": c._csrf()})
    assert r.status_code == 200
    j = r.json()
    assert "items" in j and j["items"] == []

def test_empty_reports_page_has_empty_state(app, admin):
    c = _admin_client(app, admin)
    r = c._client.get("/admin/reports/security")
    assert r.status_code == 200
    assert "Security Reports" in r.text

def test_failed_test_recorded_and_retrievable(app, admin):
    c = _admin_client(app, admin)
    r = c._client.post("/api/security/lab/run", json={"test_type": "xss"}, headers={"X-CSRF-Token": c._csrf()})
    assert r.status_code == 200
    rid = r.json()["id"]
    r2 = c._client.get(f"/api/security/lab/runs/{rid}", headers={"X-CSRF-Token": c._csrf()})
    assert r2.status_code == 200
    j = r2.json()
    assert j["id"] == rid
    assert j["test_type"] in ("xss", "sqli", "traversal", "login_fail", "port_scan", "bruteforce", "custom")

def test_save_and_retrieve_roundtrip(app, admin):
    c = _admin_client(app, admin)
    r = c._client.post("/api/security/lab/run", json={"test_type": "port_scan"}, headers={"X-CSRF-Token": c._csrf()})
    assert r.status_code == 200
    rid = r.json()["id"]
    r2 = c._client.get("/api/security/lab/runs?limit=50", headers={"X-CSRF-Token": c._csrf()})
    assert any(x["id"] == rid for x in r2.json()["items"])
    r3 = c._client.get(f"/admin/reports/security/{rid}")
    assert r3.status_code == 200
    assert str(rid) in r3.text

def test_filters_query_params(app, admin):
    c = _admin_client(app, admin)
    c._client.post("/api/security/lab/run", json={"test_type": "xss"}, headers={"X-CSRF-Token": c._csrf()})
    c._client.post("/api/security/lab/run", json={"test_type": "port_scan"}, headers={"X-CSRF-Token": c._csrf()})
    r = c._client.get("/api/security/lab/runs?test_type=xss&limit=50", headers={"X-CSRF-Token": c._csrf()})
    assert r.status_code == 200
    items = r.json()["items"]
    assert all(x["test_type"] == "xss" for x in items)
    assert len(items) >= 1

def test_csrf_still_enforced(app, admin):
    from app.main import create_app
    c = _admin_client(create_app(), admin)
    r = c._client.post("/api/security/lab/run", json={"test_type": "xss"})
    assert r.status_code in (403, 401, 422)

def test_theme_persistence_in_new_page(app, admin):
    c = _admin_client(app, admin)
    r = c._client.get("/admin/reports/security")
    assert "theme.css" in r.text or "theme.js" in r.text

def test_ai_review_and_logs_still_work(app, admin):
    c = _admin_client(app, admin)
    assert c._client.get("/admin/training").status_code == 200
    assert c._client.get("/admin/logs").status_code == 200
    assert c._client.get("/admin/security").status_code == 200
