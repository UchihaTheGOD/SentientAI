"""Public/private separation: the public website must never expose
security activity, and the private security workspace must enforce
its boundaries server-side.

Tiering (see app/api/cyberllm.py, app/api/sentinel.py):
- Anonymous: readiness endpoints answer 200 with liveness fields
  only, because the Security Lab's backend manager polls
  /api/cyberllm/readiness without a session to learn whether the
  backend answers. Operational detail stays behind authentication.
- Signed-in users: full readiness detail, the security workspace,
  and their own analysis results.
- Admins only: system incident history, automation, AI review,
  security events, blocks, and model loading.

Nothing here is enforced by hiding UI elements: every assertion
below checks the HTTP response or the data the route actually
passes to the template.
"""

from app.models.sentinel_incident import SentinelIncident


def _incident(db):
    row = SentinelIncident(log_text="suspicious test log line for separation")
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def test_readiness_is_minimal_for_anonymous(client):
    r = client.get("/api/cyberllm/readiness")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"ready", "state"}
    for field in ("model_root", "adapter_dir", "adapter_sha256",
                  "device", "quantization", "load_ms", "rss_mb"):
        assert field not in body

    r = client.get("/api/sentinel/readiness")
    assert r.status_code == 200
    body = r.json()
    assert body["classifier"] == "cyberllm"
    assert body["rules_available"] is True
    for field in ("model_root", "adapter_dir", "device", "rss_mb"):
        assert field not in body


def test_readiness_is_full_for_authenticated(auth_client):
    body = auth_client.get("/api/cyberllm/readiness").json()
    for field in ("model_root", "adapter_dir", "adapter_sha256",
                  "device", "quantization"):
        assert field in body
    body = auth_client.get("/api/sentinel/readiness").json()
    assert body["legacy_models"] == "removed"
    assert "model_root" in body


def test_security_pages_require_login(client):
    for path in ("/sentinel", "/cyberllm"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 303
        assert "/login" in r.headers["location"]


def test_security_apis_reject_anonymous_and_non_admin(app, auth_client):
    # NOTE: a fresh Client(app) is the never-signed-in jar here:
    # auth_client wraps the shared `client`, so `client` is already
    # authenticated once auth_client is requested in the same test.
    from tests.conftest import Client

    anon = Client(app)
    for path in ("/api/sentinel/incidents", "/api/security/events"):
        assert anon.get(path).status_code == 401
        assert auth_client.get(path).status_code == 403
    assert anon.get("/admin/automation").status_code == 303
    assert auth_client.get("/admin/automation").status_code == 403


def test_sentinel_page_shows_incidents_only_to_admins(db, auth_client, admin_client):
    inc = _incident(db)
    admin_html = admin_client.get("/sentinel").text
    assert "Recent incidents" in admin_html
    assert f"#{inc.id}" in admin_html
    user_html = auth_client.get("/sentinel").text
    assert "Recent incidents" not in user_html
    assert f"#{inc.id}" not in user_html


def test_security_pages_use_security_chrome_not_public_chrome(auth_client):
    for path in ("/sentinel", "/cyberllm"):
        html = auth_client.get(path).text
        assert "security-nav" in html
        assert "SentientAI Security" in html
        assert "primary-nav" not in html
        assert 'href="/explore"' not in html


def test_public_pages_show_no_security_records(db, client):
    inc = _incident(db)
    for path in ("/", "/explore"):
        html = client.get(path).text
        assert "Recent incidents" not in html
        assert f"#{inc.id}" not in html
