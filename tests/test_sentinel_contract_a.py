"""CyberLLM output contract — strict JSON schema validation, honest failures.

Replaces the old Sentinel output contract tests: the Sentinel structured
format (Summary/Indicators/Reasoning/Provisional assessment/Input status)
was retired with its models. The same validation intent is now exercised
against CyberLLMv1's JSON schema (app/services/cyberllm_schema.py):
valid JSON passes, missing/invalid fields fail, and callers degrade to
needs_review rather than inventing a verdict.
"""
from app.services.cyberllm_schema import validate, parse_model_output


def test_validate_accepts_valid():
    obj = {"classification": "likely_benign", "confidence": "high",
           "summary": "Benign log with normal access.",
           "indicators": ["2024-01-01 10:00:00 INFO GET / 200", "IP 192.168.1.1 single request"],
           "reasoning": "Single benign request with 200 status, no repeated failures."}
    cleaned, ok = validate(obj)
    assert ok is True and cleaned["classification"] == "likely_benign"


def test_validate_rejects_missing():
    cleaned, ok = validate({"classification": "likely_benign", "confidence": "high"})
    assert ok is False and cleaned is None


def test_validate_rejects_empty_summary():
    cleaned, ok = validate({"classification": "likely_benign", "confidence": "high", "summary": ""})
    assert ok is False


def test_validate_rejects_invalid_classification():
    cleaned, ok = validate({"classification": "definitely_threat", "confidence": "high", "summary": "Test."})
    assert ok is False


def test_validate_rejects_invalid_confidence():
    cleaned, ok = validate({"classification": "likely_benign", "confidence": "certain", "summary": "Test."})
    assert ok is False


def test_parse_invalid_not_valid():
    cleaned, ok = parse_model_output("likely_threat attack confirmed!!!")
    assert ok is False and cleaned is None


def test_parse_empty_not_valid():
    cleaned, ok = parse_model_output("")
    assert ok is False and cleaned is None


def test_parse_drops_unknown_keys():
    cleaned, ok = parse_model_output('{"classification": "likely_benign", "confidence": "low", "summary": "Ok.", "mitre_id": "T1059", "extra": 1}')
    assert ok is True
    assert "mitre_id" not in cleaned and "extra" not in cleaned
