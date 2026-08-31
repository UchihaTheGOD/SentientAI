"""Training example curation — score, review, promote, export.

Two rules shape this module.

1. **Nothing is promoted automatically.** A row arrives as `CANDIDATE` and stays
   there until an admin calls `review_example`. `safe_to_train` is set only by
   `TrainingExample.apply_review`, which also records who decided and when.
2. **Rejected rows are kept.** The previous version deleted them, which threw
   away the only record of what the pipeline got wrong. Rejection is now a
   status change plus a reason from a fixed vocabulary, so the filtered-out set
   stays available for error analysis.

Export only ever emits rows where `is_trainable` is true, and only from the
`train` split, so evaluation data cannot leak into a fine-tune.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.learning import (
    APPROVED, CANDIDATE, DUPLICATE, EXAMPLE_STATUSES, NEEDS_EDIT, REJECTED,
    REJECTION_REASONS, SPLIT_EVAL, SPLIT_TRAIN,
)
from app.models.security_event import SecurityEvent
from app.models.training_example import TrainingExample

PENDING_STATUSES = (CANDIDATE, NEEDS_EDIT)


# ---------------------------------------------------------------------------
# De-duplication
# ---------------------------------------------------------------------------

def dedup_hash(instruction: str, input_text: str) -> str:
    """Stable fingerprint of what an example teaches.

    Whitespace and case are normalised so two submissions that differ only in
    formatting collapse onto one hash. The output text is deliberately excluded:
    two examples with the same prompt but different answers are a labelling
    conflict, not two useful rows.
    """
    normalised = re.sub(r"\s+", " ", f"{instruction or ''}\n{input_text or ''}").strip().lower()
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()


def find_duplicate(db: Session, digest: str, exclude_id: int | None = None) -> Optional[TrainingExample]:
    query = db.query(TrainingExample).filter(TrainingExample.dedup_hash == digest)
    if exclude_id is not None:
        query = query.filter(TrainingExample.id != exclude_id)
    return query.order_by(TrainingExample.id.asc()).first()


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------

def get_pending_examples(db: Session, limit: int = 50) -> List[TrainingExample]:
    """Candidates awaiting a human, best-scoring first.

    Ordering by score means a reviewer sees the examples most likely to be worth
    keeping before the noise, rather than whatever happened to arrive last.
    """
    return (
        db.query(TrainingExample)
        .filter(TrainingExample.status.in_(PENDING_STATUSES))
        .order_by(
            TrainingExample.quality_score.desc(),
            TrainingExample.created_at.desc(),
        )
        .limit(limit)
        .all()
    )


def get_approved_examples(db: Session, split: str | None = None) -> List[TrainingExample]:
    """Approved AND human-cleared rows. `safe_to_train` is checked, not assumed."""
    query = db.query(TrainingExample).filter(
        TrainingExample.status == APPROVED,
        TrainingExample.safe_to_train == True,  # noqa: E712 — SQL, not Python
    )
    if split is not None:
        query = query.filter(TrainingExample.split == split)
    return query.order_by(TrainingExample.created_at.desc()).all()


def get_rejected_examples(db: Session, limit: int = 200) -> List[TrainingExample]:
    """Kept on purpose: this is the record of what was filtered out and why."""
    return (
        db.query(TrainingExample)
        .filter(TrainingExample.status.in_((REJECTED, DUPLICATE)))
        .order_by(TrainingExample.reviewed_at.desc())
        .limit(limit)
        .all()
    )


def status_counts(db: Session) -> dict[str, int]:
    """How many examples sit at each stage. Unknown/legacy values fold into
    `candidate`, matching `TrainingExample.state`."""
    counts = {state: 0 for state in EXAMPLE_STATUSES}
    rows = (
        db.query(TrainingExample.status, func.count(TrainingExample.id))
        .group_by(TrainingExample.status)
        .all()
    )
    for status, count in rows:
        key = status if status in counts else CANDIDATE
        counts[key] += count or 0
    return counts


def band_counts(db: Session) -> dict[str, int]:
    """Triage-band distribution across the pending queue.

    Read straight off `quality_band`, the advisory label the scorer wrote at
    collection time. Only pending rows are counted: once a human has ruled, the
    band is history, not a to-do.
    """
    counts: dict[str, int] = {}
    rows = (
        db.query(TrainingExample.quality_band, func.count(TrainingExample.id))
        .filter(TrainingExample.status.in_(PENDING_STATUSES))
        .group_by(TrainingExample.quality_band)
        .all()
    )
    for band, count in rows:
        counts[band or "unscored"] = count or 0
    return counts


def examples_for_user(db: Session, user_id: int, limit: int = 50) -> List[TrainingExample]:
    """Candidates derived from one account's own lab submissions.

    Joined through `SecurityEvent` so a user only ever sees knowledge collected
    from their own activity — never another account's observations.
    """
    return (
        db.query(TrainingExample)
        .join(SecurityEvent, TrainingExample.event_id == SecurityEvent.id)
        .filter(SecurityEvent.user_id == user_id)
        .order_by(TrainingExample.created_at.desc())
        .limit(limit)
        .all()
    )


# ---------------------------------------------------------------------------
# Human review — the only path to `safe_to_train`
# ---------------------------------------------------------------------------

def review_example(
    db: Session,
    example_id: int,
    reviewer_id: int,
    new_status: str,
    *,
    note: str | None = None,
    human_label: str | None = None,
) -> Optional[TrainingExample]:
    """Apply one reviewer decision. Returns None if the row does not exist."""
    if new_status not in EXAMPLE_STATUSES:
        raise ValueError(f"Unknown example status: {new_status}")
    example = db.query(TrainingExample).filter(TrainingExample.id == example_id).first()
    if example is None:
        return None

    if new_status == APPROVED:
        # Approving is also the point where duplicates are caught: two identical
        # examples in a dataset teach nothing extra and skew the eval split.
        digest = example.dedup_hash or dedup_hash(example.instruction, example.input_text)
        example.dedup_hash = digest
        twin = find_duplicate(db, digest, exclude_id=example.id)
        if twin is not None and twin.state == APPROVED:
            example.apply_review(
                DUPLICATE, reviewer_id,
                note=f"Identical to example #{twin.id}.",
                human_label=human_label,
            )
            db.commit()
            db.refresh(example)
            return example

    example.apply_review(new_status, reviewer_id, note=note, human_label=human_label)
    db.commit()
    db.refresh(example)
    return example


def approve_example(
    db: Session, example_id: int, reviewer_id: int, note: str | None = None,
    human_label: str | None = None,
) -> Optional[TrainingExample]:
    return review_example(
        db, example_id, reviewer_id, APPROVED, note=note, human_label=human_label,
    )


def reject_example(
    db: Session, example_id: int, reviewer_id: int, reason: str = "other",
    note: str | None = None,
) -> Optional[TrainingExample]:
    """Mark an example rejected. The row is retained, never deleted.

    `reason` comes from `REJECTION_REASONS` so the rejected set stays countable;
    anything unrecognised is stored as "other" rather than silently accepted.
    """
    if reason not in REJECTION_REASONS:
        reason = "other"
    detail = f"reason={reason}"
    if note:
        detail = f"{detail}; {note}"
    return review_example(db, example_id, reviewer_id, REJECTED, note=detail)


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

def export_approved_jsonl(db: Session, split: str = SPLIT_TRAIN) -> str:
    """JSONL of trainable examples for the given split.

    The `is_trainable` check is repeated here even though the query already
    filters on it: an export is the last gate before data reaches a fine-tune,
    and a stale row that disagrees with itself should be dropped, not shipped.
    """
    lines = []
    for example in get_approved_examples(db, split=split):
        if not example.is_trainable:
            continue
        lines.append(json.dumps({
            "instruction": example.instruction,
            "input": example.input_text,
            "output": example.output_text,
            "attack_type": example.attack_type,
            "severity": example.severity,
            "source": example.source,
            "split": example.split or SPLIT_TRAIN,
            "provenance": example.provenance,
            "human_label": example.human_label,
            "reviewed_by": example.reviewed_by,
        }))
    return "\n".join(lines)


def export_eval_jsonl(db: Session) -> str:
    return export_approved_jsonl(db, split=SPLIT_EVAL)
