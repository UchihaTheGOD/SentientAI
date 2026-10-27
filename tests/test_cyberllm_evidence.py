"""Evidence-consistency tests, including the reported 5-in-60s case.

A model summary that changes the input's time window (60s -> 6s) or its
failed-attempt count must be flagged, never silently accepted. A correct
restatement must not be flagged, and an input with no stated numbers
must not be flagged either.
"""
from __future__ import annotations

import json
from unittest.mock import patch

from app.services.cyberllm_evidence import check_evidence


def test_time_window_changed_60_to_6_is_flagged():
    inp = "2026-10-24 10:00:00 host sshd: 5 failed logins within 60 seconds from 203.0.113.10"
    out = "Five failed logins were observed over 6 seconds from a single IP."
    mismatches = check_evidence(inp, out)
    assert mismatches
    assert any("60 seconds" in m and "6 seconds" in m for m in mismatches)


def test_correct_restatement_is_not_flagged():
    inp = "5 failed logins within 60 seconds from 203.0.113.10"
    out = "There were 5 failed logins within 60 seconds."
    assert check_evidence(inp, out) == []


def test_count_changed_is_flagged():
    inp = "5 failed authentication attempts in 60 seconds"
    out = "Summary: 8 failed authentication attempts were seen."
    assert check_evidence(inp, out)


def test_no_stated_numbers_is_not_flagged():
    assert check_evidence("suspicious request to /.env", "probed a config file") == []


def _post(c, payload):
    return c._client.post("/api/cyberllm/analyze", json=payload,
                          headers={"X-CSRF-Token": c._csrf()})


def test_api_downgrades_evidence_mismatch_to_needs_review(admin_client):
    raw = json.dumps({
        "summary": "Five failed logins over 6 seconds indicate a brute-force attempt.",
        "classification": "likely_threat", "confidence": "high",
        "indicators": ["5 failed logins"], "reasoning": "",
        "limitations": [], "recommended_actions": [],
    })
    with patch("app.api.cyberllm.generate",
               return_value={"raw": raw, "output_tokens": 100,
                             "truncated": False, "latency_ms": 1}):
        r = _post(admin_client, {
            "log_text": "5 failed logins within 60 seconds from 203.0.113.10",
            "kind": "log",
        })
    assert r.status_code == 200
    body = r.json()
    assert body["classification"] == "needs_review"
    assert body["model_classification"] == "likely_threat"
    assert body["decision_source"] == "evidence_mismatch"
    assert body["needs_review"] is True
    assert any("60 seconds" in lim for lim in body["limitations"])
