"""Model result shaping: no invented confidence, MITRE, or verdict."""

from ..model import EXAMPLE_CASES, mark_abstained, shape_analysis


def test_shape_full_result():
    shaped = shape_analysis(
        {"classification": "likely_threat", "model_classification": "likely_threat",
         "confidence": 0.87, "decision_source": "model", "summary": "s",
         "indicators": ["x"], "reasoning": "r", "limitations": [],
         "recommended_actions": ["a"], "deterministic_findings": [],
         "parse_ok": True, "truncated": False, "output_tokens": 42,
         "latency_ms": 1200},
        device="cpu", readiness={"ready": True, "quantization": "fp32"})
    assert shaped["classification"] == "likely_threat"
    assert shaped["confidence"] == 0.87
    assert shaped["mitre"] is None  # current API has no MITRE field
    assert shaped["device"] == "cpu"


def test_shape_empty_result_degrades_honestly():
    shaped = shape_analysis({}, readiness={})
    assert shaped["classification"] == "unknown"
    assert shaped["confidence"] is None
    assert shaped["parse_ok"] is False
    assert shaped["model_ready"] is False


def test_mark_abstained():
    shaped = shape_analysis({"classification": "likely_benign"})
    out = mark_abstained(shaped)
    assert out["classification"] == "abstained"
    assert out["needs_review"] is True
    assert "abstained" in out["note"]


def test_example_cases_cover_the_spec():
    kinds = {c["kind"] for c in EXAMPLE_CASES}
    assert {"log", "http_request", "url", "vulnerability"} <= kinds
    names = [c["name"] for c in EXAMPLE_CASES]
    assert any("SSRF" in n for n in names)
    assert any("phishing" in n.lower() or "Phishing" in n for n in names)
    assert any("injection" in n.lower() for n in names)
    assert any("Ambiguous" in n for n in names)
    for case in EXAMPLE_CASES:
        assert case["expected"] in ("likely_benign", "needs_review",
                                    "likely_threat")
