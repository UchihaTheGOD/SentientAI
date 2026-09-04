"""Review-lifecycle vocabulary for training examples.

The path from a flagged observation to a dataset row is deliberately NOT
automatic — nothing a user submits becomes training data on its own:

    candidate            TrainingExample.status == "candidate"
        ↓  human review (admin only)
    approved / rejected  TrainingExample.status in ("approved", "rejected")
        ↓  explicit, admin-only export
    training-ready       only approved rows with safe_to_train == True

Rejected examples are KEPT (never deleted) so error analysis can look at what
was filtered out and why. This module holds only the shared constants that
`TrainingExample` and the training service use; there is no ORM model here.
"""

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
    "noisy",            # content is junk / not a meaningful example
    "duplicate",        # near-identical to an existing example
    "wrong_label",      # the label attached to this example was incorrect
    "unsafe",           # would teach something harmful or operational
    "low_information",  # technically correct but teaches nothing
    "contains_pii",     # leaked personal data
    "other",
)

# Dataset splits. Evaluation data is never used for training.
SPLIT_TRAIN = "train"
SPLIT_EVAL = "eval"
SPLITS = (SPLIT_TRAIN, SPLIT_EVAL)
