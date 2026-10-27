"""CyberLLM API tests — integration of the fine-tuned model into SentientAI.

Covers the endpoint contract (auth, validation, deterministic screen,
safe degradation) using recorded pilot v8 generations for the model-output
paths, and the real loader state for the unavailable path. Tests that use
recorded generations are marked as such; live-weight inference is verified
separately (see CYBERLLM_INTEGRATION_REPORT.md) and is NOT claimed here.

Fixtures follow tests/conftest.py: throwaway SQLite DB, CSRF double-submit.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

CYBERLLM_DIR = Path.home() / "workspace" / "cyberllm"
RECORDS = json.load(open(CYBERLLM_DIR / "pilot_v8_output" / "comparison_results.json"))["candidate"]["raw"]

SSRF_TEXT = RECORDS["T1"][22]["text"]
SSRF_RAW = RECORDS["T1"][22]["raw"]
CVE_RAW = RECORDS["T4"][1]["raw"]
BENIGN_TEXT = "Oct 24 07:12:01 web-1 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"
BENIGN_RAW = RECORDS["T5"][18]["raw"]


def _post(c, url, payload):
    return c._client.post(url, json=payload, headers={"X-CSRF-Token": c._csrf()})


def test_readiness_reports_state(client):
    r = client._client.get("/api/cyberllm/readiness")
    assert r.status_code == 200
    body = r.json()
    assert body["state"] in ("not_loaded", "loaded", "failed")
    assert body["ready"] is (body["state"] == "loaded")
    assert "adapter_sha256" in body


def test_readiness_reports_quantization(client):
    r = client._client.get("/api/cyberllm/readiness")
    assert r.status_code == 200
    assert r.json()["quantization"] in ("none", "8bit")


def test_cyberllm_page_requires_login(client):
    r = client._client.get("/cyberllm", follow_redirects=False)
    assert r.status_code == 303
    assert "/login" in r.headers["location"]


def test_cyberllm_page_renders_for_user(admin_client):
    r = admin_client._client.get("/cyberllm")
    assert r.status_code == 200
    assert "CyberLLM" in r.text
    assert "csrf-token" in r.text
    # Form JS is external now (CSP script-src 'self'): the page must
    # reference it, and that file must call the analyze endpoint.
    assert "/static/js/cyberllm_form.js" in r.text
    from pathlib import Path

    js = (Path(__file__).resolve().parent.parent / "app" / "static" / "js" / "cyberllm_form.js").read_text(encoding="utf-8")
    assert "/api/cyberllm/analyze" in js


def test_screen_requires_auth(client):
    r = client._client.post("/api/cyberllm/screen", json={"text": SSRF_TEXT})
    assert r.status_code in (401, 403)


def test_screen_catches_ssrf(admin_client):
    r = _post(admin_client, "/api/cyberllm/screen", {"text": SSRF_TEXT})
    assert r.status_code == 200
    body = r.json()
    assert body["suggested_classification"] == "likely_threat"
    assert any(f["rule"] == "metadata_endpoint" for f in body["findings"])


def test_analyze_validation(admin_client):
    assert _post(admin_client, "/api/cyberllm/analyze", {"log_text": ""}).status_code == 422
    assert _post(admin_client, "/api/cyberllm/analyze", {"log_text": "x" * 9000}).status_code == 422
    assert _post(admin_client, "/api/cyberllm/analyze",
                 {"log_text": "ok", "kind": "tweet"}).status_code == 422


def test_analyze_model_unavailable_is_503_not_a_verdict(admin_client):
    from unittest.mock import patch
    from app.services.cyberllm_inference import ModelUnavailable

    # Simulate the model being unavailable without depending on local files.
    with patch(
        "app.api.cyberllm.generate",
        side_effect=ModelUnavailable("Test: model unavailable"),
    ):
        r = _post(
            admin_client,
            "/api/cyberllm/analyze",
            {"log_text": BENIGN_TEXT},
        )

    assert r.status_code == 503


def test_analyze_ssrf_override_with_recorded_generation(admin_client):
    # RECORDED generation (pilot v8 raw output), not live inference: the
    # model said likely_benign for the SSRF; the deterministic layer must
    # override it transparently.
    with patch("app.api.cyberllm.generate",
               return_value={"raw": SSRF_RAW, "output_tokens": 200,
                             "truncated": False, "latency_ms": 1}):
        r = _post(admin_client, "/api/cyberllm/analyze",
                  {"log_text": SSRF_TEXT, "kind": "http_request"})
    assert r.status_code == 200
    body = r.json()
    assert body["classification"] == "likely_threat"
    assert body["model_classification"] == "likely_benign"
    assert body["decision_source"] == "deterministic_override"
    assert "technique" not in json.dumps(body).lower()


def test_analyze_truncated_output_degrades(admin_client):
    # RECORDED generation (pilot v8 T4[1] CVE truncation), not live inference.
    cve_text = (
        "The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; "
        "Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and "
        "Windows 10 Gold, 1511, and 1607; and Windows Server 2016 allows remote attackers to "
        "execute arbitrary code via crafted packets."
    )
    with patch("app.api.cyberllm.generate",
               return_value={"raw": CVE_RAW, "output_tokens": 512,
                             "truncated": True, "latency_ms": 1}):
        r = _post(admin_client, "/api/cyberllm/analyze",
                  {"log_text": cve_text, "kind": "vulnerability"})
    assert r.status_code == 200
    body = r.json()
    assert body["classification"] == "needs_review"
    assert body["parse_ok"] is False
    assert body["raw_output"] == CVE_RAW


def test_analyze_needs_review_escalated_by_high_finding(admin_client):
    # Endpoint logic test (synthetic model output, real screen rules): a
    # needs-review verdict plus a high-severity credential-probe finding
    # escalates to likely_threat, transparently.
    scan_text = (
        '203.0.113.153 - - [24/Oct/2026:15:00:50 +0000] "GET /wp-login.php HTTP/1.1" 404 153 "-" "Mozilla/5.0"\n'
        '203.0.113.153 - - [24/Oct/2026:15:01:51 +0000] "GET /.env HTTP/1.1" 404 153 "-" "Mozilla/5.0"\n'
        '203.0.113.153 - - [24/Oct/2026:15:02:51 +0000] "GET /.git/config HTTP/1.1" 404 153 "-" "Mozilla/5.0"'
    )
    raw = json.dumps({
        "summary": "Several failed probes.", "classification": "needs_review",
        "confidence": "medium", "indicators": [], "reasoning": "",
        "limitations": [], "recommended_actions": [],
    })
    with patch("app.api.cyberllm.generate",
               return_value={"raw": raw, "output_tokens": 100,
                             "truncated": False, "latency_ms": 1}):
        r = _post(admin_client, "/api/cyberllm/analyze", {"log_text": scan_text})
    assert r.status_code == 200
    body = r.json()
    assert body["classification"] == "likely_threat"
    assert body["model_classification"] == "needs_review"
    assert body["decision_source"] == "deterministic_override"


def test_analyze_benign_with_recorded_generation(admin_client):
    # RECORDED generation (pilot v8 T5[18]), not live inference.
    with patch("app.api.cyberllm.generate",
               return_value={"raw": BENIGN_RAW, "output_tokens": 180,
                             "truncated": False, "latency_ms": 1}):
        r = _post(admin_client, "/api/cyberllm/analyze", {"log_text": BENIGN_TEXT})
    assert r.status_code == 200
    body = r.json()
    assert body["classification"] == "likely_benign"
    assert body["decision_source"] == "model"
