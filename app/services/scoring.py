"""Advisory quality scoring for training candidates.

This module answers one question — *how much should a human trust this candidate
before reading it* — and nothing more. It is:

* **Deterministic and rule-based.** No model is consulted, so the score of a
  given candidate never drifts between runs. The signals are a coarse
  moderation strength plus cheap, content-agnostic text checks.
* **Advisory only.** Scoring decides what a reviewer sees first and how a
  candidate is *triaged*; it never sets ``approved`` or ``safe_to_train``. The
  only path to a trainable row is still ``TrainingExample.apply_review`` via a
  human (see ``app/services/training.py``). A score is a hint, never a gate.

The three bands map onto the triage vocabulary:

* ``useful``  — a clear moderation signal and a well-formed answer; most likely
  worth keeping.
* ``review``  — ambiguous: no signal, thin evidence, or a duplicate of something
  already collected. A human should look before it counts.
* ``noisy``   — junk: empty/too-short input, mostly non-printable, or padded.
  Kept (never auto-deleted) but sunk to the bottom of the queue.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

# Coarse strength of the upstream signal that produced this candidate. The
# moderation review is the only producer today; the value is deliberately a
# small vocabulary, not a probability, so scoring stays a stable hint.
SIGNAL_STRONG = "strong"
SIGNAL_WEAK = "weak"
SIGNAL_NONE = "none"
SIGNALS = (SIGNAL_STRONG, SIGNAL_WEAK, SIGNAL_NONE)

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
# A helpful answer usually names a concrete action; these are cheap markers.
_DEFENSE_MARKERS = (
    "recommend", "remove", "report", "block", "review", "warn", "escalat",
    "moderat", "guideline", "policy", "context", "because",
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

    A long body made of ``spam spam spam`` teaches the shape of the padding,
    not anything useful — the eval sets built later should not reward it.
    """
    tokens = text.split()
    if len(tokens) < 8:
        return False
    unique = len(set(tokens))
    return unique / len(tokens) < 0.25


def score_candidate(
    *,
    signal: str = SIGNAL_NONE,
    instruction: str,
    input_text: str,
    output_text: str,
    is_duplicate: bool = False,
) -> ScoreResult:
    """Score a candidate 0–100 and assign a triage band.

    ``signal`` is the coarse strength of the moderation decision that produced
    this candidate (``"strong"`` / ``"weak"`` / ``"none"``). All arguments are
    already-sanitised values taken from the flagged content and the generated
    example; nothing here reads raw request state.
    """
    score = _BASE
    notes: List[str] = []
    hard_noise = False

    stripped = (input_text or "").strip()

    # --- Signal: the strongest cue that a candidate teaches something real ---
    sig = (signal or SIGNAL_NONE).lower()
    if sig == SIGNAL_STRONG:
        score += 25
        notes.append("Strong moderation signal — likely a real example.")
    elif sig == SIGNAL_WEAK:
        score += 5
        notes.append("Weak moderation signal.")
    else:
        score -= 20
        notes.append("No moderation signal — weak as a positive example.")

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
        notes.append("Answer gives a concrete recommendation.")

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


def band_for_score(score: int) -> str:
    """Map a bare score to a band using the same thresholds as `score_candidate`.

    Used to backfill legacy rows that carry a `quality_score` but no
    `quality_band` (they predate the scorer writing the band). It can only see
    the number, so it cannot reconstruct the hard-noise or duplicate overrides —
    it assigns the band the score alone implies, which is deliberately the
    softer classification.
    """
    if score >= _USEFUL_AT:
        return BAND_USEFUL
    if score >= _REVIEW_AT:
        return BAND_REVIEW
    return BAND_NOISY
