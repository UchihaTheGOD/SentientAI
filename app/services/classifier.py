"""Classification adapter: CyberLLMv1 as the single model classifier.

This is the well-defined interface between application workflows
(Sentinel-style analyze, bridge, demo, security lab) and CyberLLMv1.
It replaces the obsolete dual-model inference: previously, workflows
called ``run_dual_inference`` and received ``model_a`` / ``model_b``
texts in a Sentinel structured format. Now they call ``classify_log``
and receive one CyberLLMv1 result in its own JSON contract.

Contract (never a fabricated verdict):
- ``source`` is always ``"cyberllm"``; ``status`` is ``"ok"``,
  ``"unavailable"``, ``"unparseable"``, or ``"truncated"``.
- When the model is unavailable, unparseable, or truncated, the
  returned ``classification`` is ``"needs_review"`` with confidence
  ``"low"``, and ``model_classification`` preserves the model's own
  verdict when one was parsed (otherwise ``None``).
- Evidence mismatches (model numbers contradicting the input) and
  unjustified high-confidence threat verdicts downgrade to
  ``needs_review`` exactly as the CyberLLM API does, via the same
  ``check_evidence`` function — so the adapter cannot drift from
  the endpoint's behaviour.
- Deterministic findings (SSRF/metadata rules) are always returned
  alongside, so a workflow never loses the rules-only signal when
  the model is absent.

CyberLLMv1 itself is unchanged: same base, same adapter, same
prompt templates, same schema. This module only adapts its output
for application workflows; it does not retrain, re-prompt, or
re-interpret the model.
"""
from __future__ import annotations

import time
from typing import Any

from app.services import cyberllm_rules
from app.services.cyberllm_evidence import check_evidence
from app.services.cyberllm_inference import ModelUnavailable, generate
from app.services.cyberllm_schema import parse_model_output

_ALLOWED = {"likely_benign", "needs_review", "likely_threat"}


def classify_log(text: str, kind: str = "log", max_new_tokens: int | None = None) -> dict[str, Any]:
    """Classify one log/request with CyberLLMv1, or return an honest unavailable result."""
    findings = cyberllm_rules.screen(text)
    start = time.perf_counter()
    try:
        gen = generate(kind, text, max_new_tokens=max_new_tokens)
    except ModelUnavailable as exc:
        return {
            "source": "cyberllm", "status": "unavailable",
            "classification": "needs_review", "model_classification": None,
            "confidence": "low", "summary": "", "indicators": [], "reasoning": "",
            "limitations": [f"CyberLLMv1 unavailable: {exc}"],
            "recommended_actions": [], "deterministic_findings": findings,
            "parse_ok": False, "truncated": False, "output_tokens": 0,
            "latency_ms": int((time.perf_counter() - start) * 1000),
            "raw_output": "", "error": str(exc),
        }
    except Exception as exc:  # model failure must never become a confident verdict
        return {
            "source": "cyberllm", "status": "unavailable",
            "classification": "needs_review", "model_classification": None,
            "confidence": "low", "summary": "", "indicators": [], "reasoning": "",
            "limitations": [f"CyberLLMv1 inference failed: {type(exc).__name__}: {exc}"],
            "recommended_actions": [], "deterministic_findings": findings,
            "parse_ok": False, "truncated": False, "output_tokens": 0,
            "latency_ms": int((time.perf_counter() - start) * 1000),
            "raw_output": "", "error": str(exc),
        }
    latency_ms = int((time.perf_counter() - start) * 1000)
    cleaned, parse_ok = parse_model_output(gen["raw"])
    if not parse_ok or cleaned is None:
        return {
            "source": "cyberllm", "status": "unparseable",
            "classification": "needs_review", "model_classification": None,
            "confidence": "low",
            "summary": "Model output could not be parsed as valid JSON; no classification is asserted.",
            "indicators": [], "reasoning": "",
            "limitations": ["Model output was truncated or malformed; human review required."],
            "recommended_actions": [], "deterministic_findings": findings,
            "parse_ok": False, "truncated": bool(gen.get("truncated")),
            "output_tokens": gen.get("output_tokens", 0), "latency_ms": latency_ms,
            "raw_output": gen["raw"], "error": None,
        }
    model_cls = cleaned["classification"]
    model_text = " ".join([cleaned["summary"], cleaned["reasoning"]] + list(cleaned["indicators"]))
    mismatches = check_evidence(text, model_text)
    if (
        model_cls == "likely_threat"
        and cleaned["confidence"] == "high"
        and not cleaned["indicators"]
        and len(cleaned["reasoning"].strip()) < 20
    ):
        mismatches.append(
            "severity justification: high-confidence likely_threat with no cited indicators or reasoning"
        )
    status = "ok"
    classification = model_cls
    limitations = list(cleaned["limitations"])
    if mismatches or gen.get("truncated"):
        status = "truncated" if gen.get("truncated") and not mismatches else "evidence_mismatch"
        classification = "needs_review"
        reasons = list(mismatches)
        if gen.get("truncated"):
            reasons.append("model output hit its token budget (truncated)")
        limitations += [f"Evidence inconsistency: {r}" for r in reasons]
    return {
        "source": "cyberllm", "status": status,
        "classification": classification, "model_classification": model_cls,
        "confidence": "low" if classification == "needs_review" and model_cls != classification else cleaned["confidence"],
        "summary": cleaned["summary"], "indicators": cleaned["indicators"],
        "reasoning": cleaned["reasoning"], "limitations": limitations,
        "recommended_actions": cleaned["recommended_actions"],
        "deterministic_findings": findings, "parse_ok": True,
        "truncated": bool(gen.get("truncated")),
        "output_tokens": gen.get("output_tokens", 0), "latency_ms": latency_ms,
        "raw_output": gen["raw"], "error": None,
    }


def fuse_classification(log_text: str, classification: dict[str, Any]) -> dict[str, Any]:
    """Fuse deterministic rules with one CyberLLMv1 classification.

    Score scale is preserved from the old fusion: rules contribute
    50%. A valid, confident model classification contributes the
    other 50% (score mapping likely_benign 10 / needs_review 50 /
    likely_threat 85). When the model is unavailable, unparseable,
    or downgraded to needs_review by evidence, the fused verdict is
    the rules verdict — never a fabricated model confidence.
    A high-severity deterministic finding still overrides a benign
    model verdict, as before, and the override is recorded in the
    components, not hidden.
    """
    from app.services.security_rules import evaluate_rules

    rules = evaluate_rules(log_text)
    model_scores = {"likely_benign": 10, "needs_review": 50, "likely_threat": 85}
    components = [{"source": "rules", "verdict": rules["verdict"], "score": rules["score"], "evidence": rules["evidence"]}]
    model_cls = classification.get("classification")
    model_status = classification.get("status")
    # A model verdict counts only when it is a real, parseable,
    # non-downgraded classification. needs_review from the model is
    # already the honest fallback, so it is recorded but does not
    # move the fused score away from the rules.
    model_counts = (
        model_status == "ok"
        and model_cls in model_scores
        and model_cls != "needs_review"
    )
    if model_counts:
        ms = model_scores[model_cls]
        components.append({
            "source": "cyberllm", "verdict": model_cls, "score": ms,
            "evidence": [f"CyberLLMv1 classification '{model_cls}' (confidence {classification.get('confidence')})"],
            "status": model_status, "confidence": classification.get("confidence"),
        })
        fused_score = int(round((rules["score"] * 0.5 + ms * 0.5)))
    else:
        components.append({
            "source": "cyberllm", "verdict": None, "score": None,
            "evidence": [f"CyberLLMv1 did not contribute a confident verdict (status={model_status})"],
            "status": model_status,
        })
        fused_score = rules["score"]
    # Deterministic high-severity override, preserved from the old API:
    # SSRF/metadata findings must not be lost to a benign model verdict.
    high = [f for f in classification.get("deterministic_findings", []) if f.get("severity") == "high"]
    if high and model_cls in ("likely_benign",):
        components.append({
            "source": "deterministic_override", "verdict": "likely_threat", "score": 85,
            "evidence": [f.get("explanation", "high-severity deterministic finding") for f in high],
        })
        fused_score = max(fused_score, 65)
    if fused_score >= 65:
        fused_verdict = "likely_threat"
    elif fused_score >= 35:
        fused_verdict = "needs_review"
    else:
        fused_verdict = "likely_benign"
    return {
        "fused_score": fused_score, "fused_verdict": fused_verdict,
        "rules": rules, "components": components,
        "model_classification": model_cls, "model_status": model_status,
        "note": "Fused from deterministic rules (50%) and a single CyberLLMv1 classification (50% when confident); agreement between two obsolete models no longer exists.",
    }
