"""Candidate scoring: an advisory triage hint, never a promotion gate.

The scorer decides queue order and a band label from the detection telemetry and
cheap text checks. These tests pin the two things that matter: the bands track
the evidence the way a reviewer would expect, and — most importantly — scoring
never touches the promotion gate. A high score is still just a candidate.
"""
from __future__ import annotations

from app.services import analysis as analysis_service
from app.services import scoring
from app.services.scoring import BAND_NOISY, BAND_REVIEW, BAND_USEFUL
from app.models.training_example import TrainingExample

STRONG_ANSWER = (
    "This is a SQL injection attempt. Use parameterised queries and validate input."
)


def _score(**overrides):
    args = dict(
        detected=True,
        attack_category="SQL Injection",
        severity="high",
        patterns_matched=["' OR 1=1", "tautology"],
        instruction="Analyse the observation and explain how to defend against it.",
        input_text="A login parameter contained ' OR 1=1 -- against the lab form.",
        output_text=STRONG_ANSWER,
        is_duplicate=False,
    )
    args.update(overrides)
    return scoring.score_candidate(**args)


# ---------------------------------------------------------------------------
# Bands track the evidence
# ---------------------------------------------------------------------------

def test_concrete_evidence_and_a_real_answer_scores_useful():
    result = _score()
    assert result.band == BAND_USEFUL
    assert result.score >= scoring._USEFUL_AT
    assert any("Detection matched" in n for n in result.notes)


def test_no_detection_falls_to_review():
    result = _score(detected=False, attack_category="none", severity="info",
                    patterns_matched=[])
    assert result.band == BAND_REVIEW
    assert result.score < scoring._USEFUL_AT
    assert any("No attack detected" in n for n in result.notes)


def test_empty_input_is_hard_noise():
    result = _score(input_text="   ")
    # A hard signal sinks the row to noisy even though detection matched.
    assert result.band == BAND_NOISY
    assert any("too short" in n.lower() for n in result.notes)


def test_mostly_nonprintable_input_is_noisy():
    result = _score(input_text="ok " + "\x00\x01\x02\x03\x04\x05\x06\x07" * 6)
    assert result.band == BAND_NOISY
    assert any("non-printable" in n.lower() for n in result.notes)


def test_a_duplicate_never_reaches_useful():
    strong = _score()
    dup = _score(is_duplicate=True)
    assert strong.band == BAND_USEFUL
    # Same content, but flagged as already-collected: capped at review so a
    # human confirms a second copy is worth keeping.
    assert dup.band == BAND_REVIEW
    assert dup.score == strong.score - 30
    assert any("uplicate" in n for n in dup.notes)


def test_padded_input_is_penalised():
    padded = _score(input_text="payload " * 40)
    assert any("repetitive" in n.lower() or "padded" in n.lower() for n in padded.notes)


def test_the_score_is_clamped_to_the_range():
    floor = _score(detected=False, patterns_matched=[], input_text="",
                   output_text="")
    assert 0 <= floor.score <= 100


# ---------------------------------------------------------------------------
# Integration: the pipeline persists the score, and scoring never promotes
# ---------------------------------------------------------------------------

def test_the_pipeline_scores_a_detected_submission(db, user):
    analysis_service.analyze_lab_submission(
        db=db, user_id=user.id, lab_id="sqli_login", lab_category="sqli",
        payload="' OR 1=1 --", lab_result={"vulnerable": True, "output": "x"},
    )
    example = db.query(TrainingExample).first()
    assert example.quality_band == BAND_USEFUL
    assert example.quality_score >= scoring._USEFUL_AT
    assert example.quality_notes
    # The gate is untouched — a good score is still only a candidate.
    assert example.safe_to_train is False
    assert example.status == "candidate"


def test_a_second_identical_submission_is_flagged_duplicate_at_collection(db, user):
    payload = "' OR 1=1 --"
    for _ in range(2):
        analysis_service.analyze_lab_submission(
            db=db, user_id=user.id, lab_id="sqli_login", lab_category="sqli",
            payload=payload, lab_result={"vulnerable": True, "output": "x"},
        )
    rows = db.query(TrainingExample).order_by(TrainingExample.id.asc()).all()
    assert len(rows) == 2
    # The first is not a duplicate of anything; the second sees its twin and is
    # sunk out of the useful band even though the content is strong.
    assert rows[0].quality_band == BAND_USEFUL
    assert rows[1].quality_band == BAND_REVIEW
    assert "uplicate" in (rows[1].quality_notes or "")
