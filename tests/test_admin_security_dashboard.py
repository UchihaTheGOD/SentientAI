"""Admin Security Dashboard tests.

GET /admin/security/dashboard is admin-only, read-only analytics: logins,
signups, login attacks (brute-force) and attack detections over the last
30 days, plus Sentinel, scanner and CyberLLM counts. Charts are
server-rendered; every chart has its numbers in an adjacent table.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.models.attact_assessment import AttactAssessment, AttactFinding, SecurityEvent
from app.models.audit import AuditEvent
from app.models.cyberllm_analysis import CyberLLMAnalysisEvent
from app.models.sentinel_incident import SentinelIncident

NOW = datetime.now(timezone.utc)


def _seed(db):
    """Seed a known, small data set. The admin login that the fixture
    performs adds exactly one auth.login AuditEvent (and no SecurityEvent),
    which the expected totals below account for."""
    for _ in range(2):
        db.add(AuditEvent(event_type="auth.login", created_at=NOW))
    for _ in range(3):
        db.add(AuditEvent(event_type="auth.login_failed", created_at=NOW))
    for _ in range(7):
        db.add(AuditEvent(event_type="auth.register", created_at=NOW))
    for _ in range(5):
        db.add(SecurityEvent(
            event_type="auth.brute_force", category="auth", severity="high",
            source="auth", ip_address="203.0.113.9",
            ip_hash="deadbeefcafe1234", created_at=NOW,
        ))
    db.add(SecurityEvent(
        event_type="attact.finding", category="web", severity="medium",
        source="attact", created_at=NOW, evidence="SQLi probe detected",
    ))
    db.add(SentinelIncident(
        log_text="failed login burst", fused_verdict="threat",
        status="pending_review", created_at=NOW,
    ))
    db.add(AttactAssessment(
        run_id="test-run-1", target="http://127.0.0.1:8000",
        status="completed", created_at=NOW,
    ))
    db.add(AttactFinding(
        assessment_id=1, check_name="sqli", title="SQLi check",
        status="confirmed", severity="high", confidence="high",
        created_at=NOW,
    ))
    db.add(CyberLLMAnalysisEvent(
        kind="log", classification="likely_benign", confidence="high",
        decision_source="model", truncated=0, latency_ms=120, created_at=NOW,
    ))
    db.add(CyberLLMAnalysisEvent(
        kind="url", classification="likely_threat", confidence="high",
        decision_source="deterministic_override", truncated=0,
        latency_ms=90, created_at=NOW,
    ))
    db.commit()


def test_dashboard_anonymous_redirects_to_login(client):
    r = client._client.get("/admin/security/dashboard", follow_redirects=False)
    assert r.status_code == 303
    assert "/login" in r.headers["location"]


def test_dashboard_non_admin_gets_403(auth_client):
    r = auth_client._client.get("/admin/security/dashboard")
    assert r.status_code == 403


def test_dashboard_renders_for_admin(admin_client, db):
    _seed(db)
    r = admin_client._client.get("/admin/security/dashboard")
    assert r.status_code == 200
    text = r.text
    assert "Security Dashboard" in text
    assert "<svg" in text  # server-rendered charts
    # Totals row: logins 2 seeded + 1 admin login, failed 3, signups 7,
    # brute-force 5, security events 6, incidents 1, assessments 1, CyberLLM 2.
    # Failed-login rate 3 / (3 + 3) = 50.0%.
    assert "<td>3</td><td>3</td><td>50.0%</td><td>7</td><td>5</td><td>6</td><td>1</td><td>1</td><td>2</td>" in text
    # Brute-force sources are salted IP hashes, never raw IPs.
    assert "deadbeefcafe" in text
    assert "203.0.113.9" not in text
    # Breakdowns and recent events.
    assert "auth.brute_force" in text
    assert "likely_threat" in text
    assert "SQLi probe detected" in text
    assert "threat" in text  # Sentinel verdict
    # Range selector.
    assert "days=7" in text and "days=90" in text


def test_dashboard_counts_match_sql(admin_client, db):
    """The totals on the page match direct counts on the same tables."""
    _seed(db)
    r = admin_client._client.get("/admin/security/dashboard")
    assert r.status_code == 200
    # Brute-force: 5 seeded; security events: 6 seeded.
    assert db.query(SecurityEvent).filter(SecurityEvent.event_type == "auth.brute_force").count() == 5
    assert db.query(SecurityEvent).count() == 6
    assert db.query(CyberLLMAnalysisEvent).count() == 2
    assert "<td>5</td>" in r.text  # brute-force total appears in the totals row


def test_dashboard_empty_database_renders(admin_client):
    r = admin_client._client.get("/admin/security/dashboard")
    assert r.status_code == 200
    assert "Security Dashboard" in r.text
    assert "No brute-force events in this period." in r.text
    assert "No security events in this period." in r.text


def test_security_center_still_works(admin_client):
    """The dashboard is additive: the existing Security Center is unchanged."""
    r = admin_client._client.get("/admin/security")
    assert r.status_code == 200
    assert "Security Center" in r.text
    assert "Security Dashboard" in r.text  # nav link present
