"""Security Reports GUI — incident linking + honest model outputs + no-crash."""
from __future__ import annotations

def _admin_client(app, admin):
    from tests.conftest import Client
    c = Client(app); c.login(admin.username); return c

def test_link_to_incident_when_created(app, admin, monkeypatch):
    import app.services.classifier as _clf
    c = _admin_client(app, admin)
    r = c._client.post("/api/security/lab/run", json={"test_type": "xss"}, headers={"X-CSRF-Token": c._csrf()})
    assert r.status_code == 200
    rid = r.json()["id"]
    def fake_run(text, kind="log", max_new_tokens=None):
        return {"source": "cyberllm", "status": "ok", "classification": "likely_threat", "confidence": "high",
                "summary": "XSS indicator observed", "indicators": ["script tag"], "reasoning": "reflected input",
                "limitations": [], "deterministic_findings": [], "parse_ok": True, "truncated": False,
                "output_tokens": 40, "latency_ms": 5, "raw_output": "", "error": None}
    monkeypatch.setattr(_clf, "classify_log", fake_run)
    r2 = c._client.post("/api/security/lab/analyze", json={"lab_run_id": rid}, headers={"X-CSRF-Token": c._csrf()})
    assert r2.status_code == 200
    j = r2.json()
    assert j.get("incident_id") is not None
    r3 = c._client.get(f"/api/security/lab/runs/{rid}", headers={"X-CSRF-Token": c._csrf()})
    assert r3.json().get("incident_id") == j["incident_id"]
    r4 = c._client.get(f"/admin/reports/security/{rid}")
    assert str(j["incident_id"]) in r4.text

def test_honest_empty_model_output(app, admin, monkeypatch):
    import app.services.classifier as _clf
    c = _admin_client(app, admin)
    r = c._client.post("/api/security/lab/run", json={"test_type": "xss"}, headers={"X-CSRF-Token": c._csrf()})
    assert r.status_code == 200
    rid = r.json()["id"]
    def fake_empty(text, kind="log", max_new_tokens=None):
        return {"source": "cyberllm", "status": "unparseable", "classification": "needs_review", "confidence": "low",
                "summary": "", "indicators": [], "reasoning": "", "limitations": [], "deterministic_findings": [],
                "parse_ok": False, "truncated": False, "output_tokens": 0, "latency_ms": 2, "raw_output": "", "error": None}
    monkeypatch.setattr(_clf, "classify_log", fake_empty)
    r2 = c._client.post("/api/security/lab/analyze", json={"lab_run_id": rid}, headers={"X-CSRF-Token": c._csrf()})
    assert r2.status_code == 200
    j = r2.json()
    assert j["classification"]["status"] == "unparseable"
    assert "fusion" in j and j["fusion"]["fused_verdict"] in ("likely_threat", "needs_review", "likely_benign")
    r3 = c._client.get(f"/admin/reports/security/{rid}")
    assert r3.status_code == 200
    assert r3.status_code == 200

def test_reports_page_does_not_crash_on_missing_model(app, admin, monkeypatch):
    import app.services.classifier as _clf
    c = _admin_client(app, admin)
    r = c._client.post("/api/security/lab/run", json={"test_type": "port_scan"}, headers={"X-CSRF-Token": c._csrf()})
    rid = r.json()["id"]
    def fake_unavail(text, kind="log", max_new_tokens=None):
        return {"source": "cyberllm", "status": "unavailable", "classification": "needs_review", "confidence": "low",
                "summary": "", "indicators": [], "reasoning": "", "limitations": [], "deterministic_findings": [],
                "parse_ok": False, "truncated": False, "output_tokens": 0, "latency_ms": 0, "raw_output": "", "error": None}
    monkeypatch.setattr(_clf, "classify_log", fake_unavail)
    c._client.post("/api/security/lab/analyze", json={"lab_run_id": rid}, headers={"X-CSRF-Token": c._csrf()})
    r2 = c._client.get("/admin/reports/security")
    assert r2.status_code == 200
    r3 = c._client.get(f"/admin/reports/security/{rid}")
    assert r3.status_code == 200

def test_malformed_model_text_does_not_crash_reports(app, admin, monkeypatch):
    import app.services.classifier as _clf
    c = _admin_client(app, admin)
    r = c._client.post("/api/security/lab/run", json={"test_type": "login_fail"}, headers={"X-CSRF-Token": c._csrf()})
    rid = r.json()["id"]
    def fake_garbage(text, kind="log", max_new_tokens=None):
        return {"source": "cyberllm", "status": "unparseable", "classification": "needs_review", "confidence": "low",
                "summary": "", "indicators": [], "reasoning": "", "limitations": [], "deterministic_findings": [],
                "parse_ok": False, "truncated": False, "output_tokens": 0, "latency_ms": 2, "raw_output": "!!!@@@### not structured", "error": None}
    monkeypatch.setattr(_clf, "classify_log", fake_garbage)
    r2 = c._client.post("/api/security/lab/analyze", json={"lab_run_id": rid}, headers={"X-CSRF-Token": c._csrf()})
    assert r2.status_code == 200
    r3 = c._client.get(f"/admin/reports/security/{rid}")
    assert r3.status_code == 200
    # fusion should still be present (rules fallback)
    assert r2.json()["fusion"]["fused_verdict"] is not None
