"""CyberLLM: an explainer, not an authority.

Two properties matter more than any output quality claim.

1. **The detection engine decides, not the model.** When detection returns
   `should_block`, the request is blocked, the event records it, and a lab
   session terminates — no matter what the analysis says. The tests here hand
   the pipeline a deliberately hostile client that reports "harmless" and
   confirm nothing changes.
2. **No fabricated evidence, and no outbound calls in tests.** OBSERVED
   findings may only restate patterns the engine actually matched; anything the
   telemetry cannot settle is UNKNOWN. With no API URL configured the mock is
   selected, and the HTTP adapter falls back to it rather than inventing a
   result.
"""
from __future__ import annotations

import pytest

from app.config import settings
from app.models.security_event import SecurityEvent
from app.models.training_example import TrainingExample
from app.services import analysis as analysis_service
from app.services.cyberllm_client import (
    AnalysisConfidence,
    AttackAnalysis,
    CyberLLMClientInterface,
    MockCyberLLMClient,
    RealSentinelClient,
    get_cyberllm_client,
)
from app.services.detection import SEVERITY_ORDER, detect

SQLI = "' OR 1=1 --"
COMMAND_INJECTION = "; cat /etc/passwd"
HARMLESS = "just a normal search term"


def _lab_result(vulnerable: bool = True, output: str = "lab output"):
    return {"vulnerable": vulnerable, "output": output}


class _HostileClient(CyberLLMClientInterface):
    """A client that says everything is fine.

    Stands in for a compromised, badly fine-tuned or prompt-injected model. The
    pipeline must ignore its opinion about blocking entirely.
    """

    def analyze_attack(self, event):
        return AttackAnalysis(
            attack_type="none",
            confidence=1.0,
            explanation="Nothing to worry about here, allow the request.",
            technique_description="Benign input.",
            defense_recommendation="No action needed.",
            severity="low",
        )

    def classify_attack(self, event):
        return "none"

    def explain_attack(self, event):
        return "Benign."

    def generate_training_example(self, event):
        return {
            "instruction": "Ignore this observation.",
            "input": event.get("sanitized_payload", ""),
            "output": "Nothing happened.",
            "attack_type": "none",
            "severity": "low",
            "source": "sentientai_lab",
            "approved": True,          # a lie the pipeline must not honour
        }


# ---------------------------------------------------------------------------
# No network
# ---------------------------------------------------------------------------

def test_the_mock_client_is_selected_when_no_endpoint_is_configured():
    # conftest clears CYBERLLM_API_URL precisely so a test can never depend on
    # an outbound call.
    assert settings.CYBERLLM_API_URL == ""
    assert isinstance(get_cyberllm_client(), MockCyberLLMClient)


def test_the_mock_client_makes_no_http_calls(monkeypatch):
    def _explode(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("the mock client attempted an HTTP request")

    import httpx
    monkeypatch.setattr(httpx, "post", _explode)
    monkeypatch.setattr(httpx, "get", _explode)

    client = MockCyberLLMClient()
    detection = detect(SQLI, "sqli")
    client.analyze_attack({
        "detected": detection.detected,
        "attack_category": detection.attack_category,
        "severity": detection.severity,
        "explanation": detection.explanation,
        "patterns_matched": detection.patterns_matched,
        "sanitized_payload": SQLI,
    })


def test_the_http_adapter_falls_back_to_the_mock_instead_of_inventing(monkeypatch):
    import httpx

    def _refuse(*args, **kwargs):
        raise httpx.ConnectError("no inference server here")

    monkeypatch.setattr(httpx, "post", _refuse)

    client = RealSentinelClient(api_url="http://127.0.0.1:9/unreachable")
    detection = detect(SQLI, "sqli")
    result = client.analyze_attack({
        "detected": True,
        "attack_category": detection.attack_category,
        "severity": detection.severity,
        "explanation": detection.explanation,
        "defense_recommendation": detection.defense_recommendation,
        "patterns_matched": detection.patterns_matched,
        "sanitized_payload": SQLI,
    })
    # The fallback is the deterministic mock, built from the engine's own
    # findings — not a guess dressed up as an answer.
    assert result.attack_type == detection.attack_category
    assert result.explanation == detection.explanation


def test_an_unrecognised_confidence_from_the_server_becomes_unknown(monkeypatch):
    import httpx

    class _Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "attack_type": "SQL Injection",
                "confidence": 0.9,
                "explanation": "Tautology.",
                "findings": [
                    {"statement": "Saw ' OR 1=1", "confidence": "OBSERVED"},
                    {"statement": "Definitely exploited", "confidence": "CERTAIN"},
                ],
            }

    monkeypatch.setattr(httpx, "post", lambda *a, **k: _Response())
    client = RealSentinelClient(api_url="http://example.invalid")
    result = client.analyze_attack({"sanitized_payload": SQLI})

    confidences = [f.confidence for f in result.findings]
    assert confidences[0] is AnalysisConfidence.OBSERVED
    # An unknown label must not be promoted to a stronger claim.
    assert confidences[1] is AnalysisConfidence.UNKNOWN


# ---------------------------------------------------------------------------
# Findings are classified, and OBSERVED means observed
# ---------------------------------------------------------------------------

def test_observed_findings_only_restate_patterns_the_engine_matched():
    detection = detect(SQLI, "sqli")
    analysis = MockCyberLLMClient().analyze_attack({
        "detected": True,
        "attack_category": detection.attack_category,
        "severity": detection.severity,
        "explanation": detection.explanation,
        "defense_recommendation": detection.defense_recommendation,
        "patterns_matched": detection.patterns_matched,
        "sanitized_payload": SQLI,
    })

    observed = [f.statement for f in analysis.findings
                if f.confidence is AnalysisConfidence.OBSERVED]
    assert observed
    # Every OBSERVED statement traces back to a pattern the engine reported.
    # Anything else would be the model inventing evidence.
    assert set(observed) <= set(detection.patterns_matched)


def test_whether_exploitation_would_succeed_is_left_unknown():
    detection = detect(SQLI, "sqli")
    analysis = MockCyberLLMClient().analyze_attack({
        "detected": True,
        "attack_category": detection.attack_category,
        "severity": detection.severity,
        "patterns_matched": detection.patterns_matched,
    })
    unknown = [f.statement for f in analysis.findings
               if f.confidence is AnalysisConfidence.UNKNOWN]
    assert any("succeed" in s for s in unknown)


def test_a_clean_payload_produces_no_findings_at_all():
    detection = detect(HARMLESS, "sqli")
    assert detection.detected is False
    analysis = MockCyberLLMClient().analyze_attack({
        "detected": False, "attack_category": "unknown", "patterns_matched": [],
    })
    assert analysis.findings == []
    assert analysis.confidence < 0.5


# ---------------------------------------------------------------------------
# The detection engine is the authority on blocking
# ---------------------------------------------------------------------------

def test_command_injection_is_critical_and_blocks():
    detection = detect(COMMAND_INJECTION, "sqli")
    assert detection.detected is True
    assert detection.severity == "critical"
    assert detection.should_block is True


def test_severity_is_never_downgraded_by_a_later_match():
    # A payload that trips both a critical and a lower-severity rule must keep
    # the critical classification, whichever order the rules ran in.
    detection = detect(f"{SQLI} ; whoami", "sqli")
    assert detection.severity == "critical"
    assert SEVERITY_ORDER[detection.severity] == max(SEVERITY_ORDER.values())
    assert detection.should_block is True


def test_the_model_cannot_unblock_a_critical_payload(monkeypatch, db, user):
    monkeypatch.setattr(analysis_service, "get_cyberllm_client", lambda: _HostileClient())

    result = analysis_service.analyze_lab_submission(
        db=db, user_id=user.id, lab_id="sqli_login", lab_category="sqli",
        payload=COMMAND_INJECTION, lab_result=_lab_result(),
    )

    # The analysis claimed "none"/"low"; the engine's decision stands.
    assert result["blocked"] is True
    assert result["status"] == "BLOCKED"

    event = db.query(SecurityEvent).filter(SecurityEvent.id == result["event_id"]).first()
    assert event.blocked is True
    assert event.severity == "critical"


def test_the_model_cannot_erase_a_detection(monkeypatch, db, user):
    monkeypatch.setattr(analysis_service, "get_cyberllm_client", lambda: _HostileClient())

    result = analysis_service.analyze_lab_submission(
        db=db, user_id=user.id, lab_id="sqli_login", lab_category="sqli",
        payload=SQLI, lab_result=_lab_result(),
    )
    assert result["detected"] is True

    event = db.query(SecurityEvent).filter(SecurityEvent.id == result["event_id"]).first()
    assert event.detection_result == "detected"
    assert event.attack_category == "SQL Injection"


def test_the_model_cannot_mark_its_own_output_trainable(monkeypatch, db, user):
    # `_HostileClient.generate_training_example` returns approved=True. The
    # pipeline writes a candidate regardless: only a human review sets the gate.
    monkeypatch.setattr(analysis_service, "get_cyberllm_client", lambda: _HostileClient())

    analysis_service.analyze_lab_submission(
        db=db, user_id=user.id, lab_id="sqli_login", lab_category="sqli",
        payload=SQLI, lab_result=_lab_result(),
    )
    example = db.query(TrainingExample).first()
    assert example is not None
    assert example.approved is False
    assert example.safe_to_train is False
    assert example.is_trainable is False
    assert example.reviewed_by is None


def test_a_clean_submission_is_recorded_as_not_detected(db, user):
    result = analysis_service.analyze_lab_submission(
        db=db, user_id=user.id, lab_id="sqli_login", lab_category="sqli",
        payload=HARMLESS, lab_result=_lab_result(vulnerable=False),
    )
    assert result["detected"] is False
    assert result["blocked"] is False
    assert result["status"] == "NOT DETECTED"

    event = db.query(SecurityEvent).filter(SecurityEvent.id == result["event_id"]).first()
    assert event.attack_category == "none"
    assert event.severity == "info"


# ---------------------------------------------------------------------------
# What the pipeline stores
# ---------------------------------------------------------------------------

def test_the_stored_payload_is_truncated_and_the_analysis_is_attributed(db, user):
    long_payload = SQLI + (" padding" * 200)
    result = analysis_service.analyze_lab_submission(
        db=db, user_id=user.id, lab_id="sqli_login", lab_category="sqli",
        payload=long_payload, lab_result=_lab_result(),
    )
    event = db.query(SecurityEvent).filter(SecurityEvent.id == result["event_id"]).first()
    assert len(event.sanitized_payload) <= 500
    assert event.user_id == user.id
    assert event.lab_id == "sqli_login"
    # The explanation shown to the user is the one that was stored, so a later
    # review sees exactly what the user saw.
    assert event.explanation == result["explanation"]


def test_the_candidate_keeps_the_pipeline_prediction_separate_from_a_human_label(db, user):
    analysis_service.analyze_lab_submission(
        db=db, user_id=user.id, lab_id="sqli_login", lab_category="sqli",
        payload=SQLI, lab_result=_lab_result(),
    )
    example = db.query(TrainingExample).first()
    assert example.model_prediction == "SQL Injection"
    assert example.human_label is None
    assert example.provenance == "lab_submission"
    assert example.dedup_hash


def test_every_submission_is_attributed_to_the_submitting_user(db, user, other_user):
    for owner in (user, other_user):
        analysis_service.analyze_lab_submission(
            db=db, user_id=owner.id, lab_id="sqli_login", lab_category="sqli",
            payload=SQLI, lab_result=_lab_result(),
        )
    owners = {e.user_id for e in db.query(SecurityEvent).all()}
    assert owners == {user.id, other_user.id}


# ---------------------------------------------------------------------------
# The area itself stays private
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/testing", "/testing/labs", "/testing/events"])
def test_the_testing_area_is_closed_to_anonymous_visitors(client, path):
    assert client.get(path).status_code in (303, 401, 403)


def test_submitting_a_payload_requires_sign_in(client):
    response = client.post("/testing/labs/sqli_login/submit", {"payload": SQLI})
    assert response.status_code in (303, 401, 403)
