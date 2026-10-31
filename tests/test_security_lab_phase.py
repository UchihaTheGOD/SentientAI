"""Lab API validation, target safety, authz, synthetic labeling."""
from __future__ import annotations

def _admin(app, admin):
    from tests.conftest import Client
    c = Client(app)
    c.login(admin.username)
    return c

def test_lab_requires_admin(app, user, admin):
    from tests.conftest import Client
    uc = Client(app); uc.login(user.username)
    r = uc._client.post("/api/security/lab/run", json={"test_type":"xss"}, headers={"X-CSRF-Token": uc._csrf()})
    assert r.status_code in (403,401)

def test_lab_target_validation(app, admin):
    c = _admin(app, admin)
    # external not allowed
    r = c._client.post("/api/security/lab/run", json={"test_type":"xss","target_url":"http://example.com/search?q=xss"}, headers={"X-CSRF-Token": c._csrf()})
    assert r.status_code == 400
    # credentials rejected
    r2 = c._client.post("/api/security/lab/run", json={"test_type":"xss","target_url":"http://user:pass@127.0.0.1:8000/search?q=xss"}, headers={"X-CSRF-Token": c._csrf()})
    assert r2.status_code == 400
    # unsupported scheme
    r3 = c._client.post("/api/security/lab/run", json={"test_type":"xss","target_url":"ftp://127.0.0.1:8000/"}, headers={"X-CSRF-Token": c._csrf()})
    assert r3.status_code == 400

def test_lab_custom_requires_string(app, admin):
    c = _admin(app, admin)
    r = c._client.post("/api/security/lab/run", json={"test_type":"custom"}, headers={"X-CSRF-Token": c._csrf()})
    assert r.status_code == 400
    r2 = c._client.post("/api/security/lab/run", json={"test_type":"custom","custom_string":"x"*301}, headers={"X-CSRF-Token": c._csrf()})
    assert r2.status_code in (400,422)

def test_lab_synthetic_labeled(app, admin):
    c = _admin(app, admin)
    r = c._client.post("/api/security/lab/run", json={"test_type":"port_scan"}, headers={"X-CSRF-Token": c._csrf()})
    assert r.status_code == 200
    j = r.json()
    assert j["is_synthetic"] is True
    assert j["detection_result"] == "synthetic"

def test_lab_real_creates_events(app, admin):
    c = _admin(app, admin)
    r = c._client.post("/api/security/lab/run", json={"test_type":"login_fail"}, headers={"X-CSRF-Token": c._csrf()})
    assert r.status_code == 200
    j = r.json()
    assert j["request_count"] == 3
    assert j["detection_result"] in ("detected","not_detected")

def test_log_analyze_validation(app, admin):
    c = _admin(app, admin)
    r = c._client.post("/api/security/lab/log-analyze", json={"log_text":""}, headers={"X-CSRF-Token": c._csrf()})
    assert r.status_code == 422
    r2 = c._client.post("/api/security/lab/log-analyze", json={"log_text":"x"*9000}, headers={"X-CSRF-Token": c._csrf()})
    assert r2.status_code == 422

def test_lab_analyze_creates_incident_and_candidate(app, admin):
    c = _admin(app, admin)
    # create lab run first
    r = c._client.post("/api/security/lab/run", json={"test_type":"xss"}, headers={"X-CSRF-Token": c._csrf()})
    assert r.status_code == 200
    lab_id = r.json()["id"]
    # analyze via event ids (use that run's events if any)
    eids = r.json()["event_ids"]
    if eids:
        r2 = c._client.post("/api/security/lab/analyze", json={"lab_run_id": lab_id}, headers={"X-CSRF-Token": c._csrf()})
    else:
        r2 = c._client.post("/api/security/lab/analyze", json={"log_text":"xss probe canary synthetic test"}, headers={"X-CSRF-Token": c._csrf()})
    assert r2.status_code in (200,422)
    if r2.status_code == 200:
        j = r2.json()
        assert "classification" in j and "fusion" in j and "model_a" not in j and "model_b" not in j
        # candidate may be None if rules benign, but incident should exist for some cases


def test_lab_detection_ignores_events_before_the_run(app, admin):
    """Detection must be attributed to the test's own window, not to
    any suspicious event from the last 15 minutes. An event seeded
    10 minutes before the run must not make a benign custom test
    report 'detected'."""
    from datetime import datetime, timedelta, timezone

    from app.database import SessionLocal
    from app.services.security_events import log_event
    from tests.conftest import Client

    s = SessionLocal()
    ev = log_event(s, event_type="suspicious_input.sqli", category="sqli",
                   severity="medium", source="middleware", route="/search",
                   method="GET", http_status=200, evidence="old probe")
    ev.created_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    s.commit()
    s.close()
    c = _admin(app, admin)
    r = c._client.post("/api/security/lab/run",
                       json={"test_type": "custom", "custom_string": "hello world"},
                       headers={"X-CSRF-Token": c._csrf()})
    assert r.status_code == 200
    assert r.json()["detection_result"] == "not_detected"


def test_list_runs_limit_clamped(app, admin):
    """Limits are clamped to [1, 50]: a negative limit must not
    defeat the cap (SQLAlchemy renders LIMIT -1 on SQLite as 'no
    limit', which used to return the whole table), and a huge limit
    must not exceed it."""
    from app.api.security_lab_api import list_runs
    from app.database import SessionLocal
    from app.models.security_lab import SecurityLabRun

    s = SessionLocal()
    for _ in range(55):
        s.add(SecurityLabRun(test_type="xss", target_url="http://127.0.0.1:8000/",
                             status="completed"))
    s.commit()
    out = list_runs(limit=-5, db=s, user=admin)
    assert len(out["items"]) == 1  # clamped to the floor, not unbounded
    out2 = list_runs(limit=500, db=s, user=admin)
    assert len(out2["items"]) == 50  # clamped to the cap
    s.close()


def test_lab_analyze_reports_input_truncation(app, admin):
    """Evidence assembled for analysis is capped (1200 per event,
    7000 total). The response must disclose when the model did not
    see the full evidence, and must not claim otherwise."""
    from app.database import SessionLocal
    from app.services.security_events import log_event
    from tests.conftest import Client

    s = SessionLocal()
    long_ev = log_event(s, event_type="suspicious_input.sqli", category="sqli",
                        severity="medium", source="middleware", route="/search",
                        method="GET", http_status=200,
                        evidence="x" * 2000)
    short_ev = log_event(s, event_type="http.200", category=None,
                         severity="low", source="middleware", route="/",
                         method="GET", http_status=200, evidence="ok")
    long_id, short_id = long_ev.id, short_ev.id
    s.close()
    c = _admin(app, admin)
    r = c._client.post("/api/security/lab/analyze",
                       json={"event_ids": [long_id]},
                       headers={"X-CSRF-Token": c._csrf()})
    assert r.status_code == 200
    j = r.json()
    assert j["input_truncated"] is True
    assert j["input_chars"] <= 7000
    r2 = c._client.post("/api/security/lab/analyze",
                        json={"event_ids": [short_id]},
                        headers={"X-CSRF-Token": c._csrf()})
    assert r2.status_code == 200
    assert r2.json()["input_truncated"] is False
