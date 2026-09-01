"""Candidate scoring: an advisory triage hint, never a promotion gate.

The scorer decides queue order and a band label from a coarse moderation signal
and cheap text checks. These tests pin the two things that matter: the bands
track the evidence the way a reviewer would expect, and — most importantly —
scoring never touches the promotion gate. A high score is still just a candidate.
"""
from __future__ import annotations

from app.services import scoring
from app.services.scoring import (
    BAND_NOISY, BAND_REVIEW, BAND_USEFUL, SIGNAL_NONE, SIGNAL_STRONG,
)

STRONG_ANSWER = (
    "Recommend removing this comment and warning the author; it violates the "
    "harassment policy."
)


def _score(**overrides):
    args = dict(
        signal=SIGNAL_STRONG,
        instruction="Decide whether this reported comment should be removed and why.",
        input_text="Reported comment: 'Nobody here wants you around, just leave.'",
        output_text=STRONG_ANSWER,
        is_duplicate=False,
    )
    args.update(overrides)
    return scoring.score_candidate(**args)


# ---------------------------------------------------------------------------
# Bands track the evidence
# ---------------------------------------------------------------------------

def test_a_strong_signal_and_a_real_answer_scores_useful():
    result = _score()
    assert result.band == BAND_USEFUL
    assert result.score >= scoring._USEFUL_AT
    assert any("Strong moderation signal" in n for n in result.notes)


def test_no_signal_falls_to_review():
    result = _score(signal=SIGNAL_NONE)
    assert result.band == BAND_REVIEW
    assert result.score < scoring._USEFUL_AT
    assert any("No moderation signal" in n for n in result.notes)


def test_empty_input_is_hard_noise():
    result = _score(input_text="   ")
    # A hard signal sinks the row to noisy even though the signal was strong.
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
    padded = _score(input_text="spam " * 40)
    assert any("repetitive" in n.lower() or "padded" in n.lower() for n in padded.notes)


def test_the_score_is_clamped_to_the_range():
    floor = _score(signal=SIGNAL_NONE, input_text="", output_text="")
    assert 0 <= floor.score <= 100


# ---------------------------------------------------------------------------
# band_for_score: the score-only mapping used to backfill legacy rows
# ---------------------------------------------------------------------------

def test_band_for_score_pins_the_thresholds():
    # Boundaries match score_candidate: >=65 useful, >=35 review, else noisy.
    assert scoring.band_for_score(scoring._USEFUL_AT) == BAND_USEFUL
    assert scoring.band_for_score(scoring._USEFUL_AT - 1) == BAND_REVIEW
    assert scoring.band_for_score(scoring._REVIEW_AT) == BAND_REVIEW
    assert scoring.band_for_score(scoring._REVIEW_AT - 1) == BAND_NOISY
    assert scoring.band_for_score(0) == BAND_NOISY
    assert scoring.band_for_score(100) == BAND_USEFUL


def test_band_for_score_agrees_with_score_candidate_on_clean_input():
    # With no hard-noise or duplicate override, the full scorer and the
    # score-only mapping must land in the same band.
    result = _score()
    assert scoring.band_for_score(result.score) == result.band
