"""The learning pipeline: nothing trains itself.

The property under test is a chain of gates, so the tests follow it: a
candidate arrives untrainable, only an admin can review it, approval is the
only thing that sets `safe_to_train`, rejected rows are kept rather than
deleted, duplicates collapse on approval, and the export emits the train split
only — evaluation data can never reach a fine-tune.
"""
from __future__ import annotations

import json

import pytest

from app.models.audit import AuditEvent
from app.models.learning import (
    APPROVED,
    CANDIDATE,
    DUPLICATE,
    NEEDS_EDIT,
    REJECTED,
    SPLIT_EVAL,
    SPLIT_TRAIN,
)
from app.models.training_example import TrainingExample
from app.services import training as training_service

INSTRUCTION = "Decide whether this reported comment should be removed and explain why."
INPUT_TEXT = "Reported comment: 'Nobody here wants you around, just leave.'"
OUTPUT_TEXT = "Remove it: the comment targets a person with a personal attack, which the harassment policy forbids."


def _candidate(db, **overrides) -> TrainingExample:
    """A candidate exactly as the moderation producer writes one."""
    fields = {
        "instruction": INSTRUCTION,
        "input_text": INPUT_TEXT,
        "output_text": OUTPUT_TEXT,
        "source": "moderation",
        "approved": False,
        "status": CANDIDATE,
        "safe_to_train": False,
        "model_prediction": "spam",
        "provenance": "moderation_flag",
    }
    fields.update(overrides)
    fields.setdefault(
        "dedup_hash",
        training_service.dedup_hash(fields["instruction"], fields["input_text"]),
    )
    row = TrainingExample(**fields)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


# ---------------------------------------------------------------------------
# A candidate is inert
# ---------------------------------------------------------------------------

def test_a_fresh_candidate_is_not_trainable(db):
    example = _candidate(db)
    assert example.state == CANDIDATE
    assert example.safe_to_train is False
    assert example.is_trainable is False
    assert example.reviewed_by is None


def test_a_candidate_is_excluded_from_every_export(db):
    _candidate(db)
    assert training_service.export_approved_jsonl(db) == ""
    assert training_service.export_eval_jsonl(db) == ""
    assert training_service.get_approved_examples(db) == []


def test_setting_the_legacy_boolean_alone_does_not_make_a_row_trainable(db):
    # `approved` is the legacy column. A row that has it set without going
    # through review must still not be exported, because `safe_to_train` is
    # the gate the export actually consults.
    example = _candidate(db, approved=True)
    assert example.is_trainable is False
    assert training_service.export_approved_jsonl(db) == ""


def test_an_unknown_review_status_is_refused(db):
    example = _candidate(db)
    with pytest.raises(ValueError):
        example.apply_review("promote-immediately")
    assert example.state == CANDIDATE


# ---------------------------------------------------------------------------
# Review is admin-only, and it is the only path to `safe_to_train`
# ---------------------------------------------------------------------------

def test_review_routes_are_closed_to_anonymous_visitors(client, db):
    example = _candidate(db)
    for path in (f"/admin/training/{example.id}/approve",
                 f"/admin/training/{example.id}/reject"):
        assert client.post(path, {}).status_code in (303, 401, 403), path

    db.expire_all()
    assert db.query(TrainingExample).filter(
        TrainingExample.id == example.id,
    ).first().safe_to_train is False


def test_review_routes_are_closed_to_ordinary_signed_in_users(auth_client, db):
    example = _candidate(db)
    assert auth_client.post(
        f"/admin/training/{example.id}/approve", {"note": "looks fine to me"},
    ).status_code == 403
    assert auth_client.post(
        f"/admin/training/{example.id}/reject", {"reason": "noisy"},
    ).status_code == 403

    db.expire_all()
    row = db.query(TrainingExample).filter(TrainingExample.id == example.id).first()
    assert row.state == CANDIDATE
    assert row.safe_to_train is False


def test_the_export_is_closed_to_ordinary_signed_in_users(auth_client):
    assert auth_client.get("/admin/export").status_code == 403


def test_an_admin_approval_records_who_decided(admin_client, db, admin):
    example = _candidate(db)
    response = admin_client.post(
        f"/admin/training/{example.id}/approve",
        {"note": "Correct label, useful explanation.", "label": "harassment"},
    )
    assert response.status_code == 303

    db.expire_all()
    row = db.query(TrainingExample).filter(TrainingExample.id == example.id).first()
    assert row.state == APPROVED
    assert row.safe_to_train is True
    assert row.reviewed_by == admin.id
    assert row.reviewed_at is not None
    assert row.review_note == "Correct label, useful explanation."
    # The human label is stored separately from what the pipeline guessed, so
    # the two can be compared instead of one overwriting the other.
    assert row.human_label == "harassment"
    assert row.model_prediction == "spam"


def test_reviewing_an_unknown_example_is_a_404(admin_client):
    assert admin_client.post("/admin/training/999999/approve", {}).status_code == 404
    assert admin_client.post("/admin/training/999999/reject", {}).status_code == 404


def test_each_review_decision_is_audited(admin_client, db):
    approved = _candidate(db)
    rejected = _candidate(db, instruction=INSTRUCTION + " (second variant)")
    admin_client.post(f"/admin/training/{approved.id}/approve", {})
    admin_client.post(f"/admin/training/{rejected.id}/reject", {"reason": "noisy"})

    types = {
        e.event_type for e in db.query(AuditEvent).filter(
            AuditEvent.event_type.like("training.%"),
        ).all()
    }
    assert types == {"training.candidate_approved", "training.candidate_rejected"}


# ---------------------------------------------------------------------------
# Rejection keeps the row
# ---------------------------------------------------------------------------

def test_rejection_retains_the_row_with_its_reason(admin_client, db):
    example = _candidate(db)
    assert admin_client.post(
        f"/admin/training/{example.id}/reject",
        {"reason": "wrong_label", "note": "The model called this harassment, but it is spam."},
    ).status_code == 303

    db.expire_all()
    row = db.query(TrainingExample).filter(TrainingExample.id == example.id).first()
    # Kept on purpose: this is the record of what was filtered out and why.
    assert row is not None
    assert row.state == REJECTED
    assert row.safe_to_train is False
    assert "reason=wrong_label" in row.review_note
    assert "The model called this harassment, but it is spam." in row.review_note


def test_a_rejection_reason_outside_the_vocabulary_becomes_other(db, admin):
    example = _candidate(db)
    training_service.reject_example(db, example.id, admin.id, reason="i-said-so")
    db.expire_all()
    row = db.query(TrainingExample).filter(TrainingExample.id == example.id).first()
    assert "reason=other" in row.review_note


def test_rejected_rows_are_listed_for_error_analysis(db, admin):
    kept = _candidate(db)
    training_service.reject_example(db, kept.id, admin.id, reason="noisy")
    listed = training_service.get_rejected_examples(db)
    assert [r.id for r in listed] == [kept.id]


def test_a_rejected_row_never_reaches_an_export(db, admin):
    example = _candidate(db)
    training_service.approve_example(db, example.id, admin.id)
    assert training_service.export_approved_jsonl(db) != ""

    training_service.reject_example(db, example.id, admin.id, reason="unsafe")
    db.expire_all()
    assert training_service.export_approved_jsonl(db) == ""
    assert db.query(TrainingExample).filter(TrainingExample.id == example.id).count() == 1


# ---------------------------------------------------------------------------
# De-duplication
# ---------------------------------------------------------------------------

def test_the_dedup_hash_ignores_formatting_and_case(db):
    a = training_service.dedup_hash("Explain  THIS", "a  comment\n")
    b = training_service.dedup_hash("explain this", "a comment")
    assert a == b


def test_the_dedup_hash_does_not_fold_in_the_answer(db):
    # Two examples with the same prompt but different answers are a labelling
    # conflict worth surfacing, not two copies of one row.
    first = _candidate(db)
    second = _candidate(db, output_text="Actually this is fine, allow it.")
    assert first.dedup_hash == second.dedup_hash


def test_approving_a_second_identical_example_marks_it_duplicate(db, admin):
    first = _candidate(db)
    second = _candidate(db, output_text="A differently worded but equivalent answer.")

    training_service.approve_example(db, first.id, admin.id)
    result = training_service.approve_example(db, second.id, admin.id)

    assert result.state == DUPLICATE
    assert result.safe_to_train is False
    assert f"#{first.id}" in result.review_note
    # One row exported, not two.
    assert len(training_service.export_approved_jsonl(db).splitlines()) == 1


def test_two_genuinely_different_examples_both_approve(db, admin):
    first = _candidate(db)
    second = _candidate(db, input_text="A second reported comment with different wording.")

    training_service.approve_example(db, first.id, admin.id)
    training_service.approve_example(db, second.id, admin.id)

    assert len(training_service.export_approved_jsonl(db).splitlines()) == 2


def test_a_duplicate_of_a_rejected_example_is_allowed_through(db, admin):
    # Only an *approved* twin blocks approval. A rejected row is a record of a
    # bad decision, not a claim on the content.
    first = _candidate(db)
    training_service.reject_example(db, first.id, admin.id, reason="noisy")

    second = _candidate(db, output_text="A corrected answer.")
    result = training_service.approve_example(db, second.id, admin.id)
    assert result.state == APPROVED


# ---------------------------------------------------------------------------
# Splits — evaluation data must not leak into training
# ---------------------------------------------------------------------------

def test_the_train_export_excludes_the_eval_split(db, admin):
    train_row = _candidate(db, split=SPLIT_TRAIN)
    eval_row = _candidate(db, split=SPLIT_EVAL,
                          input_text="A held-out observation kept for scoring.")
    training_service.approve_example(db, train_row.id, admin.id)
    training_service.approve_example(db, eval_row.id, admin.id)

    train_lines = training_service.export_approved_jsonl(db).splitlines()
    eval_lines = training_service.export_eval_jsonl(db).splitlines()
    assert len(train_lines) == 1
    assert len(eval_lines) == 1
    assert json.loads(train_lines[0])["split"] == SPLIT_TRAIN
    assert json.loads(eval_lines[0])["split"] == SPLIT_EVAL
    # No content in common: contamination would make the eval score meaningless.
    assert json.loads(train_lines[0])["input"] != json.loads(eval_lines[0])["input"]


def test_the_export_carries_provenance_and_the_reviewer(db, admin):
    example = _candidate(db)
    training_service.approve_example(db, example.id, admin.id, human_label="harassment")
    row = json.loads(training_service.export_approved_jsonl(db).splitlines()[0])
    assert row["provenance"] == "moderation_flag"
    assert row["reviewed_by"] == admin.id
    assert row["human_label"] == "harassment"
    assert row["source"] == "moderation"


def test_the_export_drops_a_row_that_disagrees_with_itself(db, admin):
    example = _candidate(db)
    training_service.approve_example(db, example.id, admin.id)
    # A stale row: status says approved, the gate says no. The export re-checks
    # `is_trainable` rather than trusting the query filter alone.
    example.safe_to_train = False
    db.commit()
    assert training_service.export_approved_jsonl(db) == ""


# ---------------------------------------------------------------------------
# Queue and counts
# ---------------------------------------------------------------------------

def test_the_pending_queue_shows_candidates_best_scoring_first(db):
    low = _candidate(db, quality_score=10)
    high = _candidate(db, quality_score=90,
                      input_text="A second, more informative observation.")
    pending = training_service.get_pending_examples(db)
    assert [p.id for p in pending] == [high.id, low.id]


def test_needs_edit_stays_in_the_queue_but_is_not_trainable(db, admin):
    example = _candidate(db)
    training_service.review_example(db, example.id, admin.id, NEEDS_EDIT,
                                   note="Rewrite the explanation.")
    db.expire_all()
    row = db.query(TrainingExample).filter(TrainingExample.id == example.id).first()
    assert row.is_pending is True
    assert row.is_trainable is False
    assert [p.id for p in training_service.get_pending_examples(db)] == [example.id]


def test_status_counts_cover_every_stage(db, admin):
    approved = _candidate(db)
    rejected = _candidate(db, input_text="A different observation entirely.")
    _candidate(db, input_text="A third observation, left alone.")
    training_service.approve_example(db, approved.id, admin.id)
    training_service.reject_example(db, rejected.id, admin.id, reason="noisy")

    counts = training_service.status_counts(db)
    assert counts[CANDIDATE] == 1
    assert counts[APPROVED] == 1
    assert counts[REJECTED] == 1


def test_a_legacy_row_with_no_status_is_treated_as_a_candidate(db):
    example = _candidate(db, status="")
    assert example.state == CANDIDATE
    assert example.is_trainable is False
    assert training_service.status_counts(db)[CANDIDATE] == 1


# ---------------------------------------------------------------------------
# The admin review-queue pages and the needs-edit action
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/admin/training", "/admin/training/rejected"])
def test_the_queue_pages_are_admin_only(client, auth_client, admin_client, path):
    assert client.get(path).status_code in (303, 401, 403)   # anonymous
    assert auth_client.get(path).status_code == 403            # ordinary user
    assert admin_client.get(path).status_code == 200           # admin


def test_the_queue_lists_a_pending_candidate(admin_client, db):
    example = _candidate(db)
    body = admin_client.get("/admin/training").text
    assert f"/admin/training/{example.id}/approve" in body


def test_the_rejected_page_lists_a_rejected_candidate(admin_client, db):
    example = _candidate(db)
    admin_client.post(f"/admin/training/{example.id}/reject", {"reason": "noisy"})
    body = admin_client.get("/admin/training/rejected").text
    assert f"#{example.id}" in body


def test_needs_edit_action_parks_a_candidate_without_making_it_trainable(admin_client, db):
    example = _candidate(db)
    response = admin_client.post(f"/admin/training/{example.id}/needs-edit", {})
    assert response.status_code == 303
    assert response.headers["location"] == "/admin/training"

    db.expire_all()
    row = db.query(TrainingExample).filter(TrainingExample.id == example.id).first()
    assert row.state == NEEDS_EDIT
    assert row.is_pending is True
    assert row.is_trainable is False


def test_the_needs_edit_action_is_admin_only(auth_client, db):
    example = _candidate(db)
    assert auth_client.post(
        f"/admin/training/{example.id}/needs-edit", {},
    ).status_code == 403
    db.expire_all()
    assert db.query(TrainingExample).filter(
        TrainingExample.id == example.id,
    ).first().state == CANDIDATE


def test_needs_edit_is_audited(admin_client, db):
    example = _candidate(db)
    admin_client.post(f"/admin/training/{example.id}/needs-edit", {})
    types = {
        e.event_type for e in db.query(AuditEvent).filter(
            AuditEvent.event_type.like("training.%"),
        ).all()
    }
    assert "training.candidate_needs_edit" in types


# ---------------------------------------------------------------------------
# The review `next` field cannot be turned into an open redirect
# ---------------------------------------------------------------------------

def test_a_review_returns_to_an_allow_listed_destination(admin_client, db):
    example = _candidate(db)
    response = admin_client.post(
        f"/admin/training/{example.id}/approve", {"next": "/admin/training"},
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/admin/training"


def test_a_review_rejects_an_off_site_next_and_falls_back(admin_client, db):
    example = _candidate(db)
    response = admin_client.post(
        f"/admin/training/{example.id}/reject",
        {"reason": "noisy", "next": "https://evil.example/phish"},
    )
    assert response.status_code == 303
    # The off-site target is discarded for the safe default, not honoured.
    assert response.headers["location"] == "/admin"
