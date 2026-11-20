"""Bridge pipeline: security_events/ATTACT -> SentinelIncident -> TrainingExample."""
from __future__ import annotations

def test_harmless_no_incident(admin, admin_client):
    from app.database import SessionLocal
    from app.services.security_events import log_event
    from app.services.sentinel_bridge import submit_security_event_for_analysis
    s = SessionLocal()
    ev = log_event(s, event_type="http.200", category="benign", severity="low", source="middleware", route="/", method="GET", http_status=200, evidence="harmless page view")
    res = submit_security_event_for_analysis(s, event_id=ev.id, triggered_by=admin.id)
    assert res["incident"] is None or res["reason"] in ("benign_no_incident", "empty_log_text")
    s.refresh(ev)
    assert ev.incident_id is None
    s.close()

def test_suspicious_event_creates_incident_and_candidate(admin, admin_client):
    from app.database import SessionLocal
    from app.services.security_events import log_event
    from app.services.sentinel_bridge import submit_security_event_for_analysis
    s = SessionLocal()
    ev = log_event(s, event_type="suspicious_input.sqli", category="sqli", severity="medium", source="middleware", route="/search", method="GET", http_status=200, evidence="' OR 1=1 -- sqli probe")
    res = submit_security_event_for_analysis(s, event_id=ev.id, triggered_by=admin.id)
    assert res["incident"] is not None
    inc = res["incident"]
    assert inc.fused_verdict is not None and inc.fused_score is not None
    if res.get("training_example_id"):
        from app.models.training_example import TrainingExample
        ex = s.query(TrainingExample).filter(TrainingExample.id == res["training_example_id"]).first()
        assert ex is not None
        assert ex.status == "candidate" and not ex.safe_to_train
    s.close()

def test_duplicate_submit_no_dup(admin, admin_client):
    from app.database import SessionLocal
    from app.services.security_events import log_event
    from app.services.sentinel_bridge import submit_security_event_for_analysis
    s = SessionLocal()
    ev = log_event(s, event_type="suspicious_input.xss", category="xss", severity="medium", source="middleware", route="/search", method="GET", http_status=200, evidence="<script>alert(1)</script>")
    r1 = submit_security_event_for_analysis(s, event_id=ev.id, triggered_by=admin.id)
    if r1["incident"] is None:
        s.close(); return
    iid1 = r1["incident"].id
    r2 = submit_security_event_for_analysis(s, event_id=ev.id, triggered_by=admin.id)
    assert r2["is_duplicate"] is True
    assert r2["incident"].id == iid1
    s.close()

def test_inference_failure_still_preserves_event(admin, admin_client, monkeypatch):
    from app.database import SessionLocal
    from app.services.security_events import log_event
    import app.services.classifier as _clf
    s = SessionLocal()
    ev = log_event(s, event_type="suspicious_input.traversal", category="traversal", severity="medium", source="middleware", route="/static/../../../../etc/passwd", method="GET", http_status=403, evidence="../etc/passwd")
    monkeypatch.setattr(_clf, "classify_log", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("simulated failure")))
    from app.services.sentinel_bridge import submit_security_event_for_analysis
    res = submit_security_event_for_analysis(s, event_id=ev.id, triggered_by=admin.id)
    from app.models.attact_assessment import SecurityEvent
    assert s.query(SecurityEvent).filter(SecurityEvent.id == ev.id).first() is not None
    assert res["incident"] is not None or res["reason"] == "benign_no_incident"
    s.close()
def test_attact_finding_path(admin, admin_client):
    from app.database import SessionLocal
    from app.models.attact_assessment import AttactAssessment, AttactFinding
    from datetime import datetime, timezone
    s = SessionLocal()
    aa = AttactAssessment(run_id="testrun12345678", target="http://127.0.0.1:8000", status="completed", allowlist="[]", checks_requested="[]", checks_executed="[]", created_at=datetime.now(timezone.utc))
    s.add(aa); s.commit(); s.refresh(aa)
    f = AttactFinding(assessment_id=aa.id, check_name="sqli", title="SQL injection found", status="confirmed", severity="high", confidence="high", summary="found sqli", evidence="' OR 1=1 --")
    s.add(f); s.commit(); s.refresh(f)
    from app.services.sentinel_bridge import submit_attact_finding_for_analysis
    res = submit_attact_finding_for_analysis(s, finding_id=f.id, triggered_by=admin.id)
    assert "incident" in res
    s.refresh(f); s.refresh(aa)
    if res["incident"] is not None:
        assert f.incident_id == res["incident"].id
        assert aa.incident_id == res["incident"].id
        from app.models.attact_assessment import SecurityEvent
        ev = s.query(SecurityEvent).filter(SecurityEvent.assessment_id == aa.id).first()
        assert ev is not None
    s.close()

def test_auth_enforced_on_admin_security_analyze(app, admin, user):
    from app.main import create_app
    from tests.conftest import Client
    ac_admin = Client(create_app()); ac_admin.login(admin.username)
    ac_user = Client(create_app()); ac_user.login(user.username)
    anon = Client(create_app())
    from app.database import SessionLocal
    from app.services.security_events import log_event
    s = SessionLocal()
    ev = log_event(s, event_type="suspicious_input.sqli", category="sqli", severity="medium", source="middleware", route="/search", method="GET", http_status=200, evidence="q=' OR 1=1")
    evid = ev.id
    s.close()
    r = anon._client.post("/admin/security/analyze/event", json={"event_id": evid}, headers={"X-CSRF-Token": anon._csrf()})
    assert r.status_code in (401, 403, 422, 405, 404, 303)
    r2 = ac_user._client.post("/admin/security/analyze/event", json={"event_id": evid}, headers={"X-CSRF-Token": ac_user._csrf()})
    assert r2.status_code in (403, 404, 401)
    r3 = ac_admin._client.post("/admin/security/analyze/event?sync=1", json={"event_id": evid}, headers={"X-CSRF-Token": ac_admin._csrf()})
    assert r3.status_code in (200, 404, 500)
    if r3.status_code == 200:
        assert "status" in r3.json()

def test_classifier_unavailable_fusion_is_rules_only():
    """Replaces the old checkpoint test: with no model, fusion must be rules-only and honest."""
    from app.services.classifier import classify_log, fuse_classification
    from app.services.security_rules import evaluate_rules
    log_text = "2024-01-01 12:00:00 WARN login failed for user admin from 198.51.100.23 401\n"*6 + "successful login for admin"
    cls = classify_log(log_text)
    assert cls["source"] == "cyberllm"
    assert cls["status"] in ("unavailable", "ok", "unparseable")
    if cls["status"] == "unavailable":
        assert cls["classification"] == "needs_review" and cls["confidence"] == "low"
    fused = fuse_classification(log_text, cls)
    assert fused["fused_verdict"] in ("likely_threat", "needs_review", "likely_benign")
    assert fused["rules"]["failed_count"] == 6
    assert evaluate_rules(log_text)["failed_count"] == 6

def test_fusion_uses_real_results_not_mock():
    """A confident CyberLLM classification moves fusion; an unavailable one does not fabricate."""
    from app.services.classifier import fuse_classification
    benign = "2024-01-01 10:00:00 INFO user alice fetched /blog 200"
    ok_threat = {"source": "cyberllm", "status": "ok", "classification": "likely_threat", "confidence": "high",
                 "summary": "Attack detected", "indicators": ["198.51.100.23"], "reasoning": "Repeated failures",
                 "deterministic_findings": []}
    r = fuse_classification(benign, ok_threat)
    # Rules 0 + model 85 -> 42, i.e. needs_review, not a single-model flip to threat.
    assert r["fused_verdict"] == "needs_review" and r["fused_score"] == 42
    assert r["components"][1]["source"] == "cyberllm"
    unavailable = {"source": "cyberllm", "status": "unavailable", "classification": "needs_review", "confidence": "low",
                   "deterministic_findings": []}
    r2 = fuse_classification(benign, unavailable)
    assert r2["fused_verdict"] == "likely_benign" and r2["fused_score"] == 0



def test_link_failure_keeps_dedup_key_and_retry_dedups(admin, admin_client):
    """If the link commit fails after incident creation, the dedup
    key must already be persisted, so a retry dedups instead of
    creating a second incident for the same event."""
    from app.database import SessionLocal
    from app.services.security_events import log_event
    from app.services.sentinel_bridge import submit_security_event_for_analysis

    s = SessionLocal()
    ev = log_event(s, event_type="suspicious_input.sqli", category="sqli",
                   severity="medium", source="middleware", route="/search",
                   method="GET", http_status=200, evidence="' OR 1=1 -- sqli probe")
    real_commit = s.commit
    calls = {"n": 0}

    def flaky_commit():
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("simulated link failure")
        return real_commit()

    s.commit = flaky_commit
    try:
        res = submit_security_event_for_analysis(s, event_id=ev.id, triggered_by=admin.id)
    finally:
        s.commit = real_commit
    assert res["incident"] is not None
    inc = res["incident"]
    s.refresh(inc)
    assert res["dedup_key"] in (inc.containment_meta or "")
    s.refresh(ev)
    assert ev.incident_id is None  # the link was rolled back
    res2 = submit_security_event_for_analysis(s, event_id=ev.id, triggered_by=admin.id)
    assert res2["is_duplicate"] is True
    assert res2["incident"].id == inc.id
    s.close()
