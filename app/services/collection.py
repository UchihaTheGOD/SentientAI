"""Collect training candidates from human moderation decisions.

This is the *producer* end of the internal Sentinel pipeline — the one place
that turns activity on the site into a training candidate. It is deliberately
narrow, because two rules from the data policy meet here:

  1. **A candidate is only ever born from a moderator's explicit decision on
     reported content.** Never from arbitrary public posts or comments. The
     material is real and a human has already judged it, which is exactly what
     makes it worth learning from — and what keeps us clear of "auto-train on
     whatever users typed."
  2. **Producing a candidate changes nothing about what is trainable.** Every
     row is written as ``CANDIDATE`` with ``safe_to_train=False``. The only path
     to a dataset is still an admin review in ``app/services/training.py``.

The candidate captures what a reviewer needs to judge the label later: the
reported content (sanitised to plain text), the decision the moderator made,
and the category the report *claimed* — stored as ``model_prediction``, i.e. a
guess to be checked at review, never asserted as fact. Scoring (see
``app/services/scoring.py``) is advisory triage only and cannot promote a row.

Nothing here is imported by a public route handler; the only caller is the
admin-only moderation flow (``app/api/moderation.py::log_action``).
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.models.blog_post import BlogPost
from app.models.learning import CANDIDATE
from app.models.moderation import REPORT_REASON_LABELS, Report
from app.models.social import Comment
from app.models.training_example import TrainingExample
from app.services import audit, scoring
from app.services import training as training_service
from app.services.sanitize import strip_formatting

logger = logging.getLogger("sentientai.collection")

# The two labels a moderation decision can teach.
_REMOVE = "remove"
_KEEP = "keep"

# Which moderation actions map to a clean keep/remove judgement on a single
# piece of content, and how strong a signal each is for the scorer. Actions not
# listed here (suspending an account, restoring content, resolving a report
# administratively) do not label one item, so they produce nothing.
_ACTION_DECISION = {
    "post_hidden":      (_REMOVE, scoring.SIGNAL_STRONG),
    "comment_hidden":   (_REMOVE, scoring.SIGNAL_STRONG),
    "post_removed":     (_REMOVE, scoring.SIGNAL_STRONG),
    "report_dismissed": (_KEEP,   scoring.SIGNAL_WEAK),
}

# Longest content snapshot we keep. A moderation example is about the decision,
# not the full article body, so a short excerpt is enough and keeps the row lean.
_MAX_CONTENT = 600
# Below this the snapshot cannot teach anything; skip rather than store noise.
_MIN_CONTENT_CHARS = 4


def _content_snapshot(db: Session, target_type: str, target_id: int) -> str | None:
    """Plain-text snapshot of the moderated item.

    Returns ``None`` when there is no single piece of content to learn from
    (a profile), or the content has since gone.
    """
    if target_type == "post":
        post = db.query(BlogPost).filter(BlogPost.id == target_id).first()
        if post is None:
            return None
        joined = "\n".join(p for p in (post.title or "", post.summary or "") if p)
        return strip_formatting(joined, _MAX_CONTENT)
    if target_type == "comment":
        comment = db.query(Comment).filter(Comment.id == target_id).first()
        if comment is None:
            return None
        return strip_formatting(comment.body, _MAX_CONTENT)
    return None


def _decision_text(verdict: str, target_type: str, reason: str | None,
                   predicted: str | None) -> str:
    """The 'answer' a reviewer is judging: what the moderator decided and why.

    Prefers the moderator's own reason. Falls back to a generic, honest summary
    that names the reported category rather than inventing a rationale.
    """
    reason = (reason or "").strip()
    if verdict == _REMOVE:
        if reason:
            return f"Remove this {target_type}. {reason}"
        label = REPORT_REASON_LABELS.get(predicted, "the community guidelines")
        return (
            f"Remove this {target_type}: a moderator reviewed the report "
            f"(“{label}”) and confirmed it violates the community guidelines."
        )
    if reason:
        return f"Keep this {target_type}. {reason}"
    return (
        f"Keep this {target_type}: a moderator reviewed the report and found it "
        f"does not violate the community guidelines."
    )


def collect_from_moderation(
    db: Session,
    *,
    action: str,
    target_type: str,
    target_id: int,
    moderator=None,
    reason: str | None = None,
    report_id: int | None = None,
    request=None,
) -> TrainingExample | None:
    """Turn one moderation decision into an unreviewed training candidate.

    Returns the new ``TrainingExample`` (always a ``CANDIDATE``), or ``None``
    when the action is not a content judgement, the content is gone, the
    snapshot is too small to teach anything, or anything goes wrong.

    It never raises and never leaves the caller's transaction dirty: a
    moderation action must succeed even if candidate collection does not.
    """
    decision = _ACTION_DECISION.get(action)
    if decision is None:
        return None
    verdict, signal = decision

    try:
        content = _content_snapshot(db, target_type, target_id)
        if not content or len(content.strip()) < _MIN_CONTENT_CHARS:
            return None

        # The category the *report* claimed. It is a guess to be checked during
        # review, so it lands in model_prediction — never in human_label, which
        # only a reviewer sets.
        predicted: str | None = None
        if report_id:
            report = db.query(Report).filter(Report.id == report_id).first()
            if report is not None:
                predicted = report.reason

        instruction = (
            f"Decide whether this reported {target_type} should be removed and explain why."
        )
        input_text = f"Reported {target_type}: '{content}'"
        output_text = _decision_text(verdict, target_type, reason, predicted)

        digest = training_service.dedup_hash(instruction, input_text)
        is_duplicate = training_service.find_duplicate(db, digest) is not None

        result = scoring.score_candidate(
            signal=signal,
            instruction=instruction,
            input_text=input_text,
            output_text=output_text,
            is_duplicate=is_duplicate,
        )

        example = TrainingExample(
            instruction=instruction,
            input_text=input_text,
            output_text=output_text,
            source="moderation",
            provenance="moderation_flag",
            status=CANDIDATE,
            approved=False,
            safe_to_train=False,
            model_prediction=predicted,
            quality_score=result.score,
            quality_band=result.band,
            quality_notes=result.notes_text or None,
            dedup_hash=digest,
        )
        db.add(example)
        db.commit()
        db.refresh(example)
    except Exception:
        db.rollback()
        logger.exception("Failed to collect a moderation training candidate")
        return None

    audit.record(
        db, "training.candidate_created", user=moderator,
        target_type="training_example", target_id=str(example.id),
        detail=f"band={example.quality_band}; from={action}", request=request,
    )
    return example
