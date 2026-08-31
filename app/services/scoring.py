"""Advisory quality scoring for training candidates.

This module answers one question — *how much should a human trust this candidate
before reading it* — and nothing more. It is:

* **Deterministic and rule-based.** No model is consulted, so the score of a
  given observation never drifts between runs. The signals are the same
  telemetry the detection engine already produced plus cheap text checks.
* **Advisory only.** Scoring decides what a reviewer sees first and how a
  candidate is *triaged*; it never sets ``approved`` or ``safe_to_train``. The
  only path to a trainable row is still ``TrainingExample.apply_review`` via a
  human (see ``app/services/training.py``). A score is a hint, never a gate.

The three bands map onto the task's triage vocabulary:

* ``useful``  — concrete detection evidence and a well-formed answer; most
  likely worth keeping.
* ``review``  — ambiguous: no attack detected, thin evidence, or a duplicate of
  something already collected. A human should look before it counts.
* ``noisy``   — junk: empty/too-short input, mostly non-printable, or padded.
  Kept (never auto-deleted) but sunk to the bottom of the queue.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Sequence

# Triage bands (persisted on TrainingExample.quality_band).
BAND_USEFUL = "useful"
BAND_REVIEW = "review"
BAND_NOISY = "noisy"
BANDS = (BAND_USEFUL, BAND_REVIEW, BAND_NOISY)

BAND_LABELS = {
    BAND_USEFUL: "Likely useful",
    BAND_REVIEW: "Needs a look",
    BAND_NOISY: "Probably noise",
}

# Score thresholds. A hard noisy signal (see below) overrides these downward.
_USEFUL_AT = 65
_REVIEW_AT = 35

_BASE = 50
_MIN, _MAX = 0, 100

# Below this many non-whitespace characters the input cannot teach anything.
_MIN_INPUT_CHARS = 4
_LONG_INPUT_CHARS = 2000
# Fraction of control/non-printable characters that marks input as junk.
_NONPRINTABLE_RATIO = 0.15
# A defensible answer usually names a mitigation; these are cheap markers.
_DEFENSE_MARKERS = (
    "defen", "parameteris", "parameteriz", "sanitis", "sanitiz", "escap",
    "validat", "encode", "prepared statement", "recommend", "mitigat",
)


@dataclass
class ScoreResult:
    """The outcome of scoring one candidate."""
    score: int
    band: str
    notes: List[str] = field(default_factory=list)

    @property
    def notes_text(self) -> str:
        return "\n".join(self.notes)


def _nonprintable_ratio(text: str) -> float:
    if not text:
        return 0.0
    bad = sum(1 for ch in text if ch != "\n" and ch != "\t" and (ord(ch) < 32 or ord(ch) == 127))
    return bad / len(text)


def _looks_padded(text: str) -> bool:
    """True when the input is dominated by one repeated token.

    A long payload made of ``padding padding padding`` teaches the shape of the
    padding, not the attack — the eval sets built later should not reward it.
    """
    tokens = text.split()
    if len(tokens) < 8:
        return False
    unique = len(set(tokens))
    return unique / len(tokens) < 0.25


def score_candidate(
    *,
    detected: bool,
    attack_category: str,
    severity: str,
    patterns_matched: Sequence[str],
    instruction: str,
    input_text: str,
    output_text: str,
    is_duplicate: bool = False,
) -> ScoreResult:
    """Score a candidate 0–100 and assign a triage band.

    All arguments are already-sanitised values taken from the detection result
    and the generated example; nothing here reads raw request state.
    """
    score = _BASE
    notes: List[str] = []
    hard_noise = False

    stripped = (input_text or "").strip()

    # --- Evidence: the strongest signal a candidate teaches something real ---
    matched = [p for p in (patterns_matched or []) if p]
    if detected and matched:
        score += 25
        preview = ", ".join(matched[:3])
        notes.append(f"Detection matched {len(matched)} pattern(s): {preview}.")
    elif detected:
        score += 5
        notes.append("Detected, but no concrete pattern was recorded.")
    else:
        score -= 20
        notes.append("No attack detected — weak as a positive example.")

    # --- Severity: a critical technique is more instructive to keep ----------
    sev = (severity or "").lower()
    sev_bonus = {"critical": 10, "high": 6, "medium": 2}.get(sev, 0)
    if sev_bonus:
        score += sev_bonus
        notes.append(f"Severity {sev}.")

    # --- Input sanity --------------------------------------------------------
    if len(stripped) < _MIN_INPUT_CHARS:
        score -= 40
        hard_noise = True
        notes.append("Input too short to be a meaningful example.")
    else:
        if len(stripped) > _LONG_INPUT_CHARS:
            score -= 10
            notes.append("Input is very long; may carry padding.")
        ratio = _nonprintable_ratio(input_text or "")
        if ratio > _NONPRINTABLE_RATIO:
            score -= 25
            hard_noise = True
            notes.append(f"Input is {int(ratio * 100)}% non-printable characters.")
        if _looks_padded(stripped):
            score -= 15
            notes.append("Input looks repetitive/padded.")

    # --- Answer quality ------------------------------------------------------
    answer = (output_text or "").strip()
    lowered = answer.lower()
    if len(answer) < 20:
        score -= 15
        notes.append("Answer is too short to be useful.")
    elif any(marker in lowered for marker in _DEFENSE_MARKERS):
        score += 10
        notes.append("Answer names a concrete defense.")

    # --- Duplication ---------------------------------------------------------
    if is_duplicate:
        score -= 30
        notes.append("Duplicate of an example already collected.")

    score = max(_MIN, min(_MAX, score))

    # --- Band ----------------------------------------------------------------
    # A hard signal (empty / mostly non-printable input) sinks a row to noisy
    # outright. Otherwise the score decides, except a duplicate never reaches
    # "useful" without a human confirming a second copy is worth keeping.
    if hard_noise:
        band = BAND_NOISY
    elif score >= _USEFUL_AT and not is_duplicate:
        band = BAND_USEFUL
    elif score >= _REVIEW_AT:
        band = BAND_REVIEW
    else:
        band = BAND_NOISY

    return ScoreResult(score=score, band=band, notes=notes)
