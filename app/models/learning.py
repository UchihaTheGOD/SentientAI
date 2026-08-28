"""Learning pipeline models — the controlled path from observation to dataset.

The pipeline is deliberately NOT automatic. Nothing a user types becomes
training data on its own. The stages are:

    raw observation          SecurityEvent (app/models/security_event.py)
        ↓  sanitize + normalise + score
    candidate               TrainingExample.status == "candidate"
        ↓  human review (admin only)
    approved / rejected     TrainingExample.status in ("approved", "rejected")
        ↓  explicit promotion by an admin
    training-ready          TrainingExample.dataset_version_id is set

`DatasetVersion` is an immutable snapshot: once frozen, the set of examples it
contains never changes, so an evaluation run can be attributed to exactly the
data it saw. `EvaluationRun` records how a checkpoint scored against a held-out
split; `ModelCheckpoint` tracks which artifact is live and guarantees we can
always roll back to a previously working one.

Rejected examples are KEPT (never deleted) so error analysis can look at what
was filtered out and why.
"""
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, String, Text,
)

from app.database import Base

# ---------------------------------------------------------------------------
# Review lifecycle for a TrainingExample
# ---------------------------------------------------------------------------
CANDIDATE = "candidate"     # collected, scored, awaiting a human
NEEDS_EDIT = "needs_edit"   # promising but the text needs fixing first
APPROVED = "approved"       # a human confirmed it is correct and useful
REJECTED = "rejected"       # a human confirmed it is wrong / noisy / unsafe
DUPLICATE = "duplicate"     # identical content already exists
EXAMPLE_STATUSES = (CANDIDATE, NEEDS_EDIT, APPROVED, REJECTED, DUPLICATE)

EXAMPLE_STATUS_LABELS = {
    CANDIDATE: "Awaiting review",
    NEEDS_EDIT: "Needs editing",
    APPROVED: "Approved",
    REJECTED: "Rejected",
    DUPLICATE: "Duplicate",
}

# Why an example was rejected — fixed vocabulary so it stays analysable.
REJECTION_REASONS = (
    "noisy",            # payload is junk / not a meaningful example
    "duplicate",        # near-identical to an existing example
    "wrong_label",      # detection or model classification was incorrect
    "unsafe",           # would teach something harmful or operational
    "low_information",  # technically correct but teaches nothing
    "contains_pii",     # leaked personal data
    "other",
)

# Dataset splits. Evaluation data is never used for training.
SPLIT_TRAIN = "train"
SPLIT_EVAL = "eval"
SPLITS = (SPLIT_TRAIN, SPLIT_EVAL)

# ModelCheckpoint lifecycle
CHECKPOINT_REGISTERED = "registered"
CHECKPOINT_EVALUATING = "evaluating"
CHECKPOINT_ACTIVE = "active"
CHECKPOINT_RETIRED = "retired"
CHECKPOINT_REJECTED = "rejected"
CHECKPOINT_STATUSES = (
    CHECKPOINT_REGISTERED, CHECKPOINT_EVALUATING,
    CHECKPOINT_ACTIVE, CHECKPOINT_RETIRED, CHECKPOINT_REJECTED,
)


class DatasetVersion(Base):
    """An immutable, named snapshot of approved training examples."""

    __tablename__ = "dataset_versions"

    id = Column(Integer, primary_key=True, index=True)
    label = Column(String(60), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    # Counts frozen at build time, so the numbers stay meaningful even if the
    # example rows are later re-labelled.
    train_count = Column(Integer, default=0, nullable=False)
    eval_count = Column(Integer, default=0, nullable=False)
    # A frozen version is closed for new examples.
    is_frozen = Column(Boolean, default=False, nullable=False)
    frozen_at = Column(DateTime, nullable=True)
    # sha256 over the ordered example content — detects accidental drift.
    content_hash = Column(String(64), nullable=True)

    @property
    def total_count(self) -> int:
        return (self.train_count or 0) + (self.eval_count or 0)


class ModelCheckpoint(Base):
    """A registered model artifact.

    We never delete or overwrite a checkpoint row. `status` moves between
    registered → evaluating → active / rejected → retired, and exactly one row
    should be `active` at a time (enforced in the service layer, which retires
    the previous active row instead of deleting it).
    """

    __tablename__ = "model_checkpoints"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), unique=True, nullable=False, index=True)
    base_model = Column(String(120), nullable=True)
    # Where the artifact lives. May be a local path or an inference URL; may be
    # NULL when only a remote endpoint is configured.
    artifact_path = Column(String(500), nullable=True)
    dataset_version_id = Column(
        Integer, ForeignKey("dataset_versions.id", ondelete="SET NULL"), nullable=True
    )
    status = Column(String(20), default=CHECKPOINT_REGISTERED, nullable=False, index=True)
    notes = Column(Text, nullable=True)
    registered_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    activated_at = Column(DateTime, nullable=True)
    retired_at = Column(DateTime, nullable=True)
    # True when the artifact was actually found on disk / reachable at register
    # time. We record what we verified rather than assuming.
    artifact_verified = Column(Boolean, default=False, nullable=False)

    @property
    def is_active(self) -> bool:
        return self.status == CHECKPOINT_ACTIVE


class EvaluationRun(Base):
    """Result of scoring a checkpoint against a dataset version's eval split."""

    __tablename__ = "evaluation_runs"
    __table_args__ = (
        Index("ix_eval_checkpoint_created", "checkpoint_id", "created_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    checkpoint_id = Column(
        Integer, ForeignKey("model_checkpoints.id", ondelete="CASCADE"), nullable=True, index=True
    )
    dataset_version_id = Column(
        Integer, ForeignKey("dataset_versions.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # Which split was scored — must be "eval" for a valid run.
    split = Column(String(10), default=SPLIT_EVAL, nullable=False)
    total = Column(Integer, default=0, nullable=False)
    correct = Column(Integer, default=0, nullable=False)
    accuracy = Column(Float, default=0.0, nullable=False)
    # True when the eval set was confirmed disjoint from the training set.
    contamination_checked = Column(Boolean, default=False, nullable=False)
    overlap_count = Column(Integer, default=0, nullable=False)
    detail = Column(Text, nullable=True)
    run_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    @property
    def accuracy_pct(self) -> int:
        return int(round((self.accuracy or 0.0) * 100))


class AnalysisFeedback(Base):
    """A user's verdict on one CyberLLM explanation.

    This is the human signal that turns a raw observation into a scored
    candidate. It is stored per (user, event) so one person cannot inflate a
    single event's score by voting repeatedly.
    """

    __tablename__ = "analysis_feedback"
    __table_args__ = (
        Index("ix_feedback_event_user", "event_id", "user_id", unique=True),
    )

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(
        Integer, ForeignKey("security_events.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    # "helpful" | "unhelpful" | "incorrect"
    verdict = Column(String(20), nullable=False, index=True)
    # Optional free-text correction from the user. Sanitised before display.
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)


FEEDBACK_VERDICTS = ("helpful", "unhelpful", "incorrect")
FEEDBACK_VERDICT_LABELS = {
    "helpful": "Helpful",
    "unhelpful": "Not helpful",
    "incorrect": "Incorrect",
}
