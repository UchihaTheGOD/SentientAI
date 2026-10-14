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

# Integration tests below drive the real producer end-to-end.
from app.models.audit import AuditEvent
from app.models.blog_post import POST_PUBLISHED, BlogPost
from app.models.learning import CANDIDATE
from app.models.moderation import REPORT_OPEN, Report
from app.models.social import Comment
from app.models.training_example import TrainingExample
from app.services import collection
from app.services import training as training_service

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


# ---------------------------------------------------------------------------
# Integration: the pipeline persists the score, and scoring never promotes
#
# These replace the coverage lost when the old security-testing producer was
# deleted. The producer is now app/services/collection.py, and the source is a
# real moderator decision on reported content — not arbitrary public text.
# ---------------------------------------------------------------------------

HARASSING = "Nobody here wants you around, just leave."


def _post(db, owner):
    post = BlogPost(
        slug="a-reported-post", title="A reported post", author=owner.username,
        user_id=owner.id, category="Community", summary="",
        content="Post body under review.", reading_time=1,
    )
    post.apply_state(POST_PUBLISHED)
    db.add(post)
    db.commit()
    db.refresh(post)
    return post


def _comment(db, author, post, body):
    comment = Comment(user_id=author.id, post_id=post.id, body=body)
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return comment


def test_a_moderation_decision_produces_a_scored_candidate(db, user, admin):
    post = _post(db, user)
    comment = _comment(db, user, post, HARASSING)

    example = collection.collect_from_moderation(
        db, action="comment_hidden", target_type="comment", target_id=comment.id,
        moderator=admin, reason="Targets a person with a personal attack.",
    )

    assert example is not None
    # Persisted, and persisted as inert: a candidate, never trainable.
    assert example.state == CANDIDATE
    assert example.safe_to_train is False
    assert example.is_trainable is False
    assert example.reviewed_by is None
    assert example.source == "moderation"
    assert example.provenance == "moderation_flag"
    # The scorer ran and its advisory hint was stored on the row.
    assert example.quality_score > 0
    assert example.quality_band in scoring.BANDS
    # The reviewer can see the reported content and the decision being judged.
    assert HARASSING in example.input_text
    assert example.output_text.lower().startswith("remove")


def test_the_produced_candidate_is_never_promoted(db, user, admin):
    post = _post(db, user)
    comment = _comment(db, user, post, HARASSING)
    collection.collect_from_moderation(
        db, action="comment_hidden", target_type="comment", target_id=comment.id,
        moderator=admin, reason="Clear harassment.",
    )
    # However well it scored, nothing reaches a dataset without an admin review.
    assert training_service.export_approved_jsonl(db) == ""
    assert training_service.get_approved_examples(db) == []


def test_the_producer_records_a_candidate_created_audit_event(db, user, admin):
    post = _post(db, user)
    comment = _comment(db, user, post, HARASSING)
    collection.collect_from_moderation(
        db, action="comment_hidden", target_type="comment", target_id=comment.id,
        moderator=admin, reason="Clear harassment.",
    )
    types = {e.event_type for e in db.query(AuditEvent).all()}
    assert "training.candidate_created" in types


def test_a_second_identical_decision_is_flagged_duplicate_at_collection(db, user, admin):
    post = _post(db, user)
    first_comment = _comment(db, user, post, HARASSING)
    second_comment = _comment(db, user, post, HARASSING)  # identical content

    first = collection.collect_from_moderation(
        db, action="comment_hidden", target_type="comment", target_id=first_comment.id,
        moderator=admin, reason="Harassment.",
    )
    second = collection.collect_from_moderation(
        db, action="comment_hidden", target_type="comment", target_id=second_comment.id,
        moderator=admin, reason="Harassment.",
    )

    assert first.quality_band == BAND_USEFUL
    # Same content: the scorer caps a duplicate below "useful" and records why,
    # so the reviewer knows a copy already exists. The row is still kept.
    assert second.quality_band != BAND_USEFUL
    assert "uplicate" in (second.quality_notes or "")
    assert db.query(TrainingExample).count() == 2


def test_a_content_free_action_produces_nothing(db, user, admin):
    # Suspending an account is a moderation action, but there is no single piece
    # of content to label, so the producer writes nothing.
    example = collection.collect_from_moderation(
        db, action="user_suspended", target_type="profile", target_id=user.id,
        moderator=admin, reason="Repeated abuse.",
    )
    assert example is None
    assert db.query(TrainingExample).count() == 0


def test_an_action_outside_the_decision_map_produces_nothing(db, user, admin):
    post = _post(db, user)
    example = collection.collect_from_moderation(
        db, action="post_restored", target_type="post", target_id=post.id,
        moderator=admin,
    )
    assert example is None
    assert db.query(TrainingExample).count() == 0


def test_the_report_reason_becomes_the_prediction_to_check(db, user, admin):
    post = _post(db, user)
    comment = _comment(db, user, post, HARASSING)
    report = Report(
        reporter_id=user.id, target_type="comment", target_id=comment.id,
        reason="harassment", status=REPORT_OPEN,
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    example = collection.collect_from_moderation(
        db, action="comment_hidden", target_type="comment", target_id=comment.id,
        moderator=admin, reason="Confirmed.", report_id=report.id,
    )
    # The reported category is a guess to check at review — model_prediction —
    # never the human's verdict. human_label stays empty until a reviewer sets it.
    assert example.model_prediction == "harassment"
    assert example.human_label is None


def test_hiding_a_comment_through_the_admin_route_collects_a_candidate(admin_client, db, user):
    # Proves the producer is actually wired into the moderation flow:
    #   admin hides content  →  ModerationAction  →  training candidate.
    post = _post(db, user)
    comment = _comment(db, user, post, HARASSING)

    response = admin_client.post(
        f"/admin/moderation/comment/{comment.id}/hide",
        {"reason": "Harassment — targets a person."},
    )
    assert response.status_code == 303

    candidate = (
        db.query(TrainingExample)
        .filter(TrainingExample.source == "moderation")
        .first()
    )
    assert candidate is not None
    assert HARASSING in candidate.input_text
    assert candidate.state == CANDIDATE
    assert candidate.safe_to_train is False
