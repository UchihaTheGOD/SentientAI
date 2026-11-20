"""Classifier adapter tests — CyberLLMv1 as the single model classifier.

All model generation is mocked here (unit level); these tests prove the
adapter contract, not real inference. Real inference is reported
separately and is NOT claimed from these tests.
"""
from __future__ import annotations

import pytest

import app.services.classifier as clf


def _fake_gen(raw, truncated=False, tokens=20):
    return {"raw": raw, "truncated": truncated, "output_tokens": tokens}


def test_classify_success(monkeypatch):
    raw = '{"classification": "likely_threat", "confidence": "high", "summary": "6 failed logins from one IP", "indicators": ["198.51.100.23"], "reasoning": "Repeated failures exceed threshold.", "limitations": [], "recommended_actions": []}'
    monkeypatch.setattr(clf, "generate", lambda kind, text, max_new_tokens=None: _fake_gen(raw))
    out = clf.classify_log("6 failed logins", kind="log")
    assert out["source"] == "cyberllm" and out["status"] == "ok"
    assert out["classification"] == "likely_threat" and out["model_classification"] == "likely_threat"
    assert out["parse_ok"] is True


def test_classify_unavailable_is_needs_review(monkeypatch):
    from app.services.cyberllm_inference import ModelUnavailable
    monkeypatch.setattr(clf, "generate", lambda *a, **kw: (_ for _ in ()).throw(ModelUnavailable("no weights")))
    out = clf.classify_log("anything")
    assert out["status"] == "unavailable"
    assert out["classification"] == "needs_review" and out["confidence"] == "low"
    assert out["model_classification"] is None


def test_classify_unparseable_is_needs_review(monkeypatch):
    monkeypatch.setattr(clf, "generate", lambda *a, **kw: _fake_gen("not json at all"))
    out = clf.classify_log("anything")
    assert out["status"] == "unparseable" and out["classification"] == "needs_review"


def test_classify_evidence_mismatch_downgrades(monkeypatch):
    # Model claims 99 failed logins, input has 1 — must not stay a confident verdict.
    raw = '{"classification": "likely_threat", "confidence": "high", "summary": "99 failed logins", "indicators": ["99 failed logins"], "reasoning": "Many failures.", "limitations": [], "recommended_actions": []}'
    monkeypatch.setattr(clf, "generate", lambda *a, **kw: _fake_gen(raw))
    out = clf.classify_log("1 failed login from 198.51.100.23")
    assert out["status"] == "evidence_mismatch"
    assert out["classification"] == "needs_review"
    assert out["model_classification"] == "likely_threat"  # original preserved


def test_classify_truncation_downgrades(monkeypatch):
    raw = '{"classification": "likely_threat", "confidence": "high", "summary": "Attack", "indicators": ["x"], "reasoning": "Enough reasoning here.", "limitations": [], "recommended_actions": []}'
    monkeypatch.setattr(clf, "generate", lambda *a, **kw: _fake_gen(raw, truncated=True))
    out = clf.classify_log("attack log")
    assert out["status"] == "truncated" and out["classification"] == "needs_review"


def test_classify_unjustified_threat_downgrades(monkeypatch):
    raw = '{"classification": "likely_threat", "confidence": "high", "summary": "Threat", "indicators": [], "reasoning": "", "limitations": [], "recommended_actions": []}'
    monkeypatch.setattr(clf, "generate", lambda *a, **kw: _fake_gen(raw))
    out = clf.classify_log("normal log")
    assert out["classification"] == "needs_review"


def test_fusion_rules_only_when_unavailable():
    from app.services.security_rules import evaluate_rules
    benign = "2024-01-01 10:00:00 INFO user alice fetched /blog 200"
    fused = clf.fuse_classification(benign, {"source": "cyberllm", "status": "unavailable", "classification": "needs_review", "confidence": "low", "deterministic_findings": []})
    assert fused["fused_verdict"] == evaluate_rules(benign)["verdict"] == "likely_benign"
    assert fused["fused_score"] == 0


def test_fusion_confident_model_moves_score():
    benign = "2024-01-01 10:00:00 INFO user alice fetched /blog 200"
    ok = {"source": "cyberllm", "status": "ok", "classification": "likely_threat", "confidence": "high",
          "summary": "Attack", "indicators": ["x"], "reasoning": "r", "deterministic_findings": []}
    fused = clf.fuse_classification(benign, ok)
    # One confident model contributes 50%: 0 -> 42, i.e. benign -> needs_review,
    # not a single-model flip to likely_threat. That is a safety property.
    assert fused["fused_verdict"] == "needs_review"
    assert fused["fused_score"] == 42  # (0*0.5 + 85*0.5), Python round-half-even


def test_fusion_ssrf_override():
    benign = "GET http://169.254.169.254/latest/meta-data/ 200"
    ok_benign = {"source": "cyberllm", "status": "ok", "classification": "likely_benign", "confidence": "high",
                 "summary": "Benign", "indicators": [], "reasoning": "Looks normal.", "deterministic_findings": []}
    # SSRF finding is computed by the adapter's rules screen, not by the fake dict here:
    from app.services import cyberllm_rules
    findings = cyberllm_rules.screen(benign)
    assert any(f["severity"] == "high" for f in findings)
    ok_benign["deterministic_findings"] = findings
    fused = clf.fuse_classification(benign, ok_benign)
    assert fused["fused_verdict"] == "likely_threat"
    assert any(c["source"] == "deterministic_override" for c in fused["components"])


def test_no_agreement_field():
    fused = clf.fuse_classification("normal", {"source": "cyberllm", "status": "unavailable", "classification": "needs_review", "confidence": "low", "deterministic_findings": []})
    assert "agreement" not in fused
    assert "model_a" not in str(fused) and "model_b" not in str(fused)
