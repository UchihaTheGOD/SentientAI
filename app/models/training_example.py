"""Training example model — curated data for the internal Sentinel assistant.

An example is a CANDIDATE until a human approves it. `approved` (the legacy
boolean) is kept in sync with `status` so older queries keep working, but
`status` is authoritative — see app/models/learning.py for the full lifecycle.

Nothing here is ever auto-promoted: `safe_to_train` only becomes True through
an explicit admin action recorded in `reviewed_by` / `reviewed_at`. Examples
originate from content-moderation review, never from arbitrary public content.
"""
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text,
)

from app.database import Base
from app.models.learning import (
    APPROVED, CANDIDATE, EXAMPLE_STATUS_LABELS, EXAMPLE_STATUSES,
    REJECTED, SPLIT_TRAIN,
)


class TrainingExample(Base):
    __tablename__ = "training_examples"
    __table_args__ = (
        Index("ix_training_status_created", "status", "created_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    instruction = Column(Text, nullable=False)
    input_text = Column(Text, nullable=False)
    output_text = Column(Text, nullable=False)
    source = Column(String(50), default="moderation")
    # Legacy boolean, kept in sync with `status`.
    approved = Column(Boolean, default=False)
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # ---- Review lifecycle -------------------------------------------------
    status = Column(String(20), default=CANDIDATE, nullable=False, index=True)
    review_note = Column(Text, nullable=True)      # why accepted / rejected
    reviewed_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)

    # ---- Automated scoring (advisory only — never auto-approves) ----------
    quality_score = Column(Integer, default=0, nullable=False, index=True)
    quality_notes = Column(Text, nullable=True)    # newline-separated reasons
    # Triage band from app/services/scoring.py: useful / review / noisy. A hint
    # for the reviewer's eye and for dataset filtering — not a promotion gate.
    quality_band = Column(String(10), nullable=True, index=True)

    # ---- Labels: what the pipeline thought vs what a human decided --------
    model_prediction = Column(String(80), nullable=True)
    human_label = Column(String(80), nullable=True)

    # ---- Promotion gate --------------------------------------------------
    safe_to_train = Column(Boolean, default=False, nullable=False, index=True)
    split = Column(String(10), default=SPLIT_TRAIN, nullable=False, index=True)

    # ---- Provenance + de-duplication -------------------------------------
    provenance = Column(String(60), default="moderation_flag", nullable=False)
    dedup_hash = Column(String(64), nullable=True, index=True)

    # -- helpers -----------------------------------------------------------
    @property
    def state(self) -> str:
        """Normalised status, tolerant of legacy rows with no `status`."""
        if self.status in EXAMPLE_STATUSES:
            return self.status
        return APPROVED if self.approved else CANDIDATE

    @property
    def state_label(self) -> str:
        return EXAMPLE_STATUS_LABELS.get(self.state, "Awaiting review")

    @property
    def is_pending(self) -> bool:
        return self.state in (CANDIDATE, "needs_edit")

    @property
    def is_trainable(self) -> bool:
        """Only approved, human-cleared examples may enter a dataset."""
        return self.state == APPROVED and bool(self.safe_to_train)

    def apply_review(
        self,
        new_status: str,
        reviewer_id: int | None = None,
        note: str | None = None,
        human_label: str | None = None,
    ) -> None:
        """Record a human review decision. The only path to `safe_to_train`."""
        if new_status not in EXAMPLE_STATUSES:
            raise ValueError(f"Unknown example status: {new_status}")
        self.status = new_status
        self.approved = new_status == APPROVED
        self.safe_to_train = new_status == APPROVED
        self.reviewed_by = reviewer_id
        self.reviewed_at = datetime.now(timezone.utc)
        self.updated_at = self.reviewed_at
        if note is not None:
            self.review_note = note
        if human_label is not None:
            self.human_label = human_label
