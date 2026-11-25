"""CyberLLM identity hardening tests.

The model is a LoRA adapter on Qwen3-1.7B. The training data names the
creator "Gaurav Bisht" (11,891 times) while the deployment system prompt
names "Gaurav Singh" — and the user's full name is Gaurav Singh Bisht, so
both short forms are parts of one name. The canonical enforced identity is
"CyberLLM developed by Gaurav Singh Bisht".

These tests cover the deterministic, code-level fix (no retraining, no
prompt change, no weight changes):
* the sanitizer rewrites Qwen/Alibaba/short-name developer claims in
  generated text to the full name, and leaves non-identity mentions alone;
* identity questions are answered directly (decision_source "identity_rule")
  without calling the model;
* readiness is tiered: anonymous callers get liveness fields only.
"""

from __future__ import annotations

from unittest.mock import patch

from app.services.cyberllm_identity import (
    IDENTITY_DEVELOPER,
    IDENTITY_STATEMENT,
    identity_answer,
    is_identity_question,
    sanitize_cleaned_fields,
    sanitize_identity_text,
)
from app.services.cyberllm_schema import parse_model_output

FULL = "Gaurav Singh Bisht"


# ---------------------------------------------------------------------------
# Sanitizer unit tests
# ---------------------------------------------------------------------------


def test_sanitizer_rewrites_qwen_self_identification():
    out, changed = sanitize_identity_text("I am Qwen, a large language model.")
    assert changed
    assert out == "I am CyberLLM, a large language model."
    assert "Qwen" not in out


def test_sanitizer_rewrites_qwen3_and_alibaba_developer():
    out, changed = sanitize_identity_text(
        "I am Qwen3, a large language model developed by Alibaba."
    )
    assert changed
    assert "Qwen" not in out and "Alibaba" not in out
    assert f"developed by {FULL}" in out
    assert out.startswith("I am CyberLLM")


def test_sanitizer_rewrites_alibaba_cloud_developer():
    out, _ = sanitize_identity_text("I was created by Alibaba Cloud.")
    assert out == f"I was developed by {FULL}."


def test_sanitizer_normalises_bisht_only_developer_to_full_name():
    out, changed = sanitize_identity_text("I was created by Gaurav Bisht.")
    assert changed
    assert out == f"I was developed by {FULL}."
    out, _ = sanitize_identity_text("My developer is Gaurav Bisht.")
    assert out == f"My developer is {FULL}."


def test_sanitizer_leaves_short_form_singh_and_full_name_alone():
    for text in (
        "I am CyberLLM, developed by Gaurav Singh.",
        f"I am CyberLLM, developed by {FULL}.",
        "I was developed by Gaurav Singh.",
    ):
        out, changed = sanitize_identity_text(text)
        assert out == text and not changed


def test_sanitizer_normalises_cyber_llm_spelling():
    out, changed = sanitize_identity_text("Cyber LLM detected a threat.")
    assert changed
    assert out == "CyberLLM detected a threat."


def test_sanitizer_leaves_non_identity_mentions_alone():
    # A log line or username that merely mentions Qwen/Bisht is evidence,
    # not an identity claim — the sanitizer must not rewrite it.
    for text in (
        "Failed login from 10.0.0.1 for user qwen.",
        "The log mentions Qwen in a URL.",
        "Username Bisht failed to log in.",
        "The Qwen model card is at /models/qwen.",
    ):
        out, changed = sanitize_identity_text(text)
        assert out == text and not changed


def test_sanitizer_is_idempotent():
    samples = [
        "I am Qwen, developed by Alibaba.",
        "I was created by Gaurav Bisht.",
        "Cyber LLM detected a threat.",
        "I am CyberLLM, developed by Gaurav Singh.",
    ]
    for text in samples:
        once, _ = sanitize_identity_text(text)
        twice, changed = sanitize_identity_text(once)
        assert twice == once and not changed


def test_sanitizer_does_not_break_json():
    raw = (
        '{"summary": "I am Qwen, developed by Alibaba.", '
        '"classification": "likely_benign", "confidence": "high", '
        '"indicators": ["created by Gaurav Bisht"], "reasoning": "Cyber LLM check.", '
        '"limitations": [], "recommended_actions": []}'
    )
    sanitized, changed = sanitize_identity_text(raw)
    assert changed
    cleaned, parse_ok = parse_model_output(sanitized)
    assert parse_ok
    assert cleaned["classification"] == "likely_benign"
    assert "Qwen" not in cleaned["summary"]
    assert FULL in cleaned["summary"]
    assert FULL in cleaned["indicators"][0]


def test_sanitize_cleaned_fields():
    cleaned = {
        "summary": "I am Qwen.",
        "reasoning": "Created by Gaurav Bisht.",
        "indicators": ["Cyber LLM", "user qwen"],
        "limitations": ["developed by Alibaba"],
        "recommended_actions": [],
        "classification": "likely_benign",
        "confidence": "high",
    }
    out = sanitize_cleaned_fields(cleaned)
    assert out["summary"] == "I am CyberLLM."
    assert FULL in out["reasoning"]
    assert out["indicators"][0] == "CyberLLM"
    # Non-identity mention inside an indicator is left alone.
    assert out["indicators"][1] == "user qwen"
    assert FULL in out["limitations"][0]
    # Input dict is not mutated.
    assert cleaned["summary"] == "I am Qwen."


def test_identity_constants_use_full_name():
    assert IDENTITY_DEVELOPER == FULL
    assert FULL in IDENTITY_STATEMENT
    assert IDENTITY_STATEMENT.startswith("I am CyberLLM,")
    assert FULL in identity_answer()


# ---------------------------------------------------------------------------
# Identity-question detection
# ---------------------------------------------------------------------------


def test_identity_questions_detected():
    for text in (
        "Who are you?",
        "who created you",
        "Who developed CyberLLM?",
        "Are you Qwen?",
        "what model are you",
        "What is CyberLLM?",
        "who is your developer",
        "What's your name?",
        "Hey, who are you?",
        "tell me about yourself",
        "introduce yourself",
        "who made you",
    ):
        assert is_identity_question(text), text


def test_non_identity_inputs_not_detected():
    for text in (
        "Failed login for user who are you",
        "GET /login HTTP/1.1",
        "Oct 24 07:12:01 web-1 sudo: deploy : TTY=pts/0",
        "https://example.com/phish",
        "who are you " + "x" * 400,
        "the user asked who are you in a chat log line",
        "",
        "   ",
    ):
        assert not is_identity_question(text), text


# ---------------------------------------------------------------------------
# API: deterministic identity path + tiered readiness
# ---------------------------------------------------------------------------


def _post(c, url, payload):
    return c._client.post(url, json=payload, headers={"X-CSRF-Token": c._csrf()})


def test_analyze_identity_question_without_model_call(admin_client, db):
    """Identity questions return the canonical identity and never call the
    model (generate must not be invoked)."""
    from app.models.cyberllm_analysis import CyberLLMAnalysisEvent

    with patch(
        "app.api.cyberllm.generate",
        side_effect=AssertionError("generate must not be called for identity questions"),
    ):
        r = _post(admin_client, "/api/cyberllm/analyze", {"log_text": "Who are you?"})

    assert r.status_code == 200
    body = r.json()
    assert body["decision_source"] == "identity_rule"
    assert body["classification"] == "likely_benign"
    assert body["confidence"] == "high"
    assert body["model_classification"] is None
    assert body["raw_output"] is None
    assert FULL in body["summary"]
    assert "CyberLLM" in body["summary"]
    # The per-call record was written.
    row = db.query(CyberLLMAnalysisEvent).order_by(CyberLLMAnalysisEvent.id.desc()).first()
    assert row is not None
    assert row.decision_source == "identity_rule"
    assert row.classification == "likely_benign"
    assert row.kind == "log"


def test_analyze_identity_question_variants(admin_client):
    with patch(
        "app.api.cyberllm.generate",
        side_effect=AssertionError("generate must not be called for identity questions"),
    ):
        for text in ("Who developed CyberLLM?", "Are you Qwen?", "What is CyberLLM?"):
            r = _post(admin_client, "/api/cyberllm/analyze", {"log_text": text})
            assert r.status_code == 200, text
            assert r.json()["decision_source"] == "identity_rule", text
            assert FULL in r.json()["summary"], text


def test_analyze_non_identity_still_calls_model(admin_client):
    """A real log is not an identity question: the model path runs."""
    from app.services.cyberllm_inference import ModelUnavailable

    with patch(
        "app.api.cyberllm.generate",
        side_effect=ModelUnavailable("Test: model unavailable"),
    ) as mocked:
        r = _post(
            admin_client,
            "/api/cyberllm/analyze",
            {"log_text": "Oct 24 07:12:01 web-1 sudo: deploy : TTY=pts/0"},
        )
    assert r.status_code == 503
    mocked.assert_called_once()


def test_analyze_sanitizes_raw_output_passthrough(admin_client):
    """An unparseable model output that claims Qwen must not reach the
    caller verbatim: the raw_output passthrough is sanitized."""
    qwen_raw = "I am Qwen, developed by Alibaba. {not json"
    with patch("app.api.cyberllm.generate", return_value={
        "raw": qwen_raw, "output_tokens": 10, "truncated": False, "latency_ms": 1,
    }):
        r = _post(admin_client, "/api/cyberllm/analyze", {"log_text": "some log line"})
    assert r.status_code == 200
    body = r.json()
    assert body["decision_source"] == "unparseable_output"
    assert "Qwen" not in body["raw_output"]
    assert "Alibaba" not in body["raw_output"]
    assert FULL in body["raw_output"]


def test_readiness_anonymous_gets_liveness_only(client):
    r = client._client.get("/api/cyberllm/readiness")
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {"ready", "state"}
    assert "base_model" not in body
    assert "adapter_sha256" not in body
    assert "model_root" not in body
    assert "adapter_dir" not in body
    assert "device" not in body


def test_readiness_authenticated_gets_full_detail(admin_client):
    r = admin_client._client.get("/api/cyberllm/readiness")
    assert r.status_code == 200
    body = r.json()
    assert body["state"] in ("not_loaded", "loaded", "failed")
    assert body["ready"] is (body["state"] == "loaded")
    assert "adapter_sha256" in body
    assert "base_model" in body
    assert "quantization" in body
    assert body["quantization"] in ("none", "8bit")


def test_sentinel_readiness_anonymous_gets_liveness_only(client):
    r = client._client.get("/api/sentinel/readiness")
    assert r.status_code == 200
    body = r.json()
    assert body["ready"] in (True, False)
    assert body["classifier"] == "cyberllm"
    assert body["rules_available"] is True
    assert "base_model" not in body
    assert "model_root" not in body
    assert "adapter_dir" not in body
    assert "device" not in body


def test_sentinel_readiness_authenticated_gets_full_detail(admin_client):
    r = admin_client._client.get("/api/sentinel/readiness")
    assert r.status_code == 200
    body = r.json()
    assert "base_model" in body
    assert "rules_available" in body
    assert "legacy_models" in body
