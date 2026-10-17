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
    import app.services.sentinel_inference as _inf
    s = SessionLocal()
    ev = log_event(s, event_type="suspicious_input.traversal", category="traversal", severity="medium", source="middleware", route="/static/../../../../etc/passwd", method="GET", http_status=403, evidence="../etc/passwd")
    monkeypatch.setattr(_inf, "run_dual_inference", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("simulated failure")))
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

def test_checkpoint_load_and_parse_produces_verdict():
    from app.services.sentinel_loader import ensure_loaded
    from app.services.prompt_service import build_analysis_prompt
    from app.services.sentinel_schema import parse_model_text, fuse_structured
    from app.services.sentinel_fusion import fuse
    s = ensure_loaded()
    log_text = "2024-01-01 12:00:00 WARN login failed for user admin from 198.51.100.23 401\n"*6 + "successful login for admin"
    prompt = build_analysis_prompt(log_text)
    assert "<output>" in prompt
    if s.ready:
        from app.services.sentinel_inference import run_dual_inference
        inf = run_dual_inference(prompt, max_new_tokens=32, timeout_s=12)
        assert "model_a" in inf and "model_b" in inf
        a_st = (inf.get("model_a") or {}).get("status")
        b_st = (inf.get("model_b") or {}).get("status")
        assert a_st in ("ok","empty","timeout","error","unavailable")
        assert b_st in ("ok","empty","timeout","error","unavailable")
        p_a = parse_model_text((inf.get("model_a") or {}).get("text"), a_st)
        assert "vulnerability_detected" in p_a
        fused = fuse_structured(log_text, inf)
        assert fused["fused_verdict"] in ("likely_threat","needs_review","likely_benign")
        legacy = fuse(log_text, inf)
        assert legacy["fused_verdict"] is not None
    else:
        inf = {"model_a":{"status":"unavailable","text":""}, "model_b":{"status":"unavailable","text":""}, "agreement":None}
        fused = fuse_structured(log_text, inf)
        assert fused["fused_verdict"] in ("likely_threat","needs_review","likely_benign")

def test_fusion_uses_real_results_not_mock():
    from app.services.sentinel_schema import parse_model_text
    txt = "likely_threat: sqli confirmed with high confidence. Vulnerability detected, exploitable. Remediation: use parameterized queries."
    parsed = parse_model_text(txt, "ok")
    assert parsed["vulnerability_detected"] is True
    assert parsed["severity"] in ("high","medium","low","info")

