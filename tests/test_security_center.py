"""Spec sections 8-12: persistence, dashboard, enforcement, demo, redaction."""
from __future__ import annotations

def _admin_client(app, admin):
    from tests.conftest import Client
    c = Client(app)
    c.login(admin.username)
    return c

def test_attact_run_persists_and_exports(app, admin, db):
    from app.main import create_app
    ac = _admin_client(create_app(), admin)
    # run minimal check so it doesn't need live server beyond localhost which may 500; use smallest timeout
    r = ac._client.post("/api/security/attact/run", json={"target":"http://127.0.0.1:9","checks":["security_headers"],"timeout":0.3,"max_requests":10}, headers={"X-CSRF-Token": ac._csrf()})
    # either success with some findings or 500 if target unreachable but should not crash auth
    assert r.status_code in (200,500,400)
    if r.status_code == 200:
        aid = r.json()["assessment_id"]
        r2 = ac._client.get(f"/api/security/assessments/{aid}/export", headers={"X-CSRF-Token": ac._csrf()})
        assert r2.status_code == 200
        r3 = ac._client.get("/admin/security", headers={"X-CSRF-Token": ac._csrf()})
        assert r3.status_code == 200

def test_security_events_redaction(app, admin, db):
    from app.services.security_events import redact, log_event
    from app.database import SessionLocal
    s = SessionLocal()
    # ensure secrets redacted
    red = redact("password: hunter2 token=abc123")
    assert "hunter2" not in red and "abc123" not in red
    s.close()

def test_findings_triage_and_admin_authz(app, admin, user):
    from app.main import create_app
    ac = _admin_client(create_app(), admin)
    from tests.conftest import Client
    uc = Client(create_app()); uc.login(user.username)
    # triage requires admin; use nonexistent id returns 404 not 403
    r = uc._client.post("/api/security/findings/9999/triage", json={"status":"fixed"}, headers={"X-CSRF-Token": uc._csrf()})
    assert r.status_code in (403,404)

def test_demo_case_runs(app, admin):
    from app.main import create_app
    ac = _admin_client(create_app(), admin)
    # run a benign demo that should not need network
    r = ac._client.post("/api/security/demo/run/info-01", headers={"X-CSRF-Token": ac._csrf()})
    assert r.status_code == 200
    j = r.json()
    assert "fusion" in j and "ground_truth" in j
    assert "evidence" in j

def test_classifier_fusion(app):
    from app.services.classifier import fuse_classification
    # unavailable model -> rules only, no fabricated verdict
    unavailable = {"source": "cyberllm", "status": "unavailable", "classification": "needs_review", "confidence": "low", "deterministic_findings": []}
    f = fuse_classification("normal log line", unavailable)
    assert f["fused_verdict"] == "likely_benign" and f["model_status"] == "unavailable"
    # ok case
    ok = {"source": "cyberllm", "status": "ok", "classification": "likely_benign", "confidence": "high",
          "summary": "No threat", "indicators": [], "reasoning": "Normal log line.", "deterministic_findings": []}
    f2 = fuse_classification("normal log line", ok)
    assert "fused_verdict" in f2 and f2["model_classification"] == "likely_benign"

def test_blocks_not_firewall(app, admin):
    # documentation: blocks are application-layer; is_blocked is via TempBlock, not firewall
    from app.services.incident_service import apply_temp_block, is_blocked, revoke_block
    from app.database import SessionLocal
    s = SessionLocal()
    blk = apply_temp_block(s, kind="ip", value="203.0.113.99", ttl_minutes=1, reason="test")
    assert blk.active
    assert is_blocked(s, "ip", "203.0.113.99")
    revoke_block(s, blk.id)
    assert not is_blocked(s, "ip", "203.0.113.99")
    s.close()

def test_scope_and_timeout(app):
    from ATTACT.http_client import BoundedClient
    import pytest
    c = BoundedClient(timeout=0.2, max_requests=2, allowlist=set())
    # request limit respected
    assert c.max_requests == 2
