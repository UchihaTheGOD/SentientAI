"""Expanded evidence-consistency coverage.

Each category has a contradiction case and a consistent control, so a
check that flags everything (or nothing) fails here.
"""
from __future__ import annotations

import json
from unittest.mock import patch

from app.services.cyberllm_evidence import check_evidence


def test_timestamp_changed_is_flagged():
    inp = "2026-10-24 10:00:00 sshd: failed login from 203.0.113.10"
    out = "At 2026-10-24 11:30:00 a failed login was seen from 203.0.113.10."
    assert any("timestamp" in m for m in check_evidence(inp, out))


def test_timestamp_unchanged_is_not_flagged():
    inp = "2026-10-24 10:00:00 sshd: failed login from 203.0.113.10"
    out = "At 2026-10-24 10:00:00 a failed login was seen from 203.0.113.10."
    assert check_evidence(inp, out) == []


def test_ip_changed_is_flagged():
    inp = "failed login from 203.0.113.10"
    out = "Failed login from 198.51.100.23."
    assert any("IP address" in m for m in check_evidence(inp, out))


def test_ip_port_changed_is_flagged():
    inp = "connection from 203.0.113.10:22"
    out = "Connection from 203.0.113.10:2222."
    assert any("port" in m for m in check_evidence(inp, out))


def test_status_code_changed_is_flagged():
    inp = "GET /admin 401"
    out = "The request returned status 403."
    assert any("HTTP status" in m for m in check_evidence(inp, out))


def test_status_code_unchanged_is_not_flagged():
    inp = "GET /admin 401"
    out = "The request returned status 401."
    assert check_evidence(inp, out) == []


def test_domain_changed_is_flagged():
    inp = "GET https://example.com/login"
    out = "A request to evil.example.org was observed."
    assert any("domain" in m for m in check_evidence(inp, out))


def test_claimed_success_vs_failed_input_is_flagged():
    inp = "login failed for user bob from 203.0.113.10"
    out = "The attacker successfully logged in as bob."
    assert any("claimed outcome" in m for m in check_evidence(inp, out))


def test_contradictory_counts_inside_output_are_flagged():
    inp = "suspicious log"
    out = "5 failed logins and also 8 failed logins were seen."
    assert any("contradictory" in m for m in check_evidence(inp, out))


def test_recommendation_only_values_are_not_checked():
    # check_evidence receives summary+reasoning+indicators only in the
    # API; a bare recommendation string is not an observed fact here.
    # This test guards the module itself: no input value -> no flag.
    assert check_evidence("suspicious request", "block port 443") == []


def _post(c, payload):
    return c._client.post("/api/cyberllm/analyze", json=payload,
                          headers={"X-CSRF-Token": c._csrf()})


def _raw(summary, classification="likely_threat", confidence="high", indicators=None, reasoning="x" * 30):
    return json.dumps({
        "summary": summary, "classification": classification,
        "confidence": confidence, "indicators": indicators or [],
        "reasoning": reasoning, "limitations": [],
        "recommended_actions": [],
    })


def test_api_truncated_generation_downgrades(admin_client):
    with patch("app.api.cyberllm.generate",
               return_value={"raw": _raw("5 failed logins within 60 seconds."),
                             "output_tokens": 320, "truncated": True, "latency_ms": 1}):
        r = _post(admin_client, {"log_text": "5 failed logins within 60 seconds", "kind": "log"})
    assert r.status_code == 200
    body = r.json()
    assert body["classification"] == "needs_review"
    assert body["decision_source"] == "truncated_output"


def test_api_unjustified_high_severity_downgrades(admin_client):
    with patch("app.api.cyberllm.generate",
               return_value={"raw": _raw("Threat detected.", indicators=[], reasoning=""),
                             "output_tokens": 50, "truncated": False, "latency_ms": 1}):
        r = _post(admin_client, {"log_text": "normal request", "kind": "log"})
    body = r.json()
    assert body["classification"] == "needs_review"
    assert body["model_classification"] == "likely_threat"
    assert any("severity justification" in lim for lim in body["limitations"])


def test_api_consistent_output_keeps_verdict(admin_client):
    with patch("app.api.cyberllm.generate",
               return_value={"raw": _raw("5 failed logins within 60 seconds from 203.0.113.10.",
                                         indicators=["5 failed logins"]),
                             "output_tokens": 50, "truncated": False, "latency_ms": 1}):
        r = _post(admin_client, {"log_text": "5 failed logins within 60 seconds from 203.0.113.10", "kind": "log"})
    body = r.json()
    assert body["classification"] == "likely_threat"
    assert body["decision_source"] == "model"
