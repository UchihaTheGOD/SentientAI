"""Analysis feedback: a signal for reviewers, never a control.

A user may tell the system whether an event's explanation was helpful. The
property under test is that this verdict stays in its lane: it is scoped to the
user's own event, stored once per (event, user), and — even when it says the
analysis was wrong — it can only *hint* to a reviewer. It never approves,
trains, or promotes anything. `safe_to_train` is reachable through human review
alone.
"""
from __future__ import annotations

from app.models.audit import AuditEvent
from app.models.learning import CANDIDATE, AnalysisFeedback
from app.models.security_event import SecurityEvent
from app.models.training_example import TrainingExample
from app.services import training as training_service
from app.services.scoring import BAND_REVIEW, BAND_USEFUL


def _event_with_candidate(db, user_id: int, *, band: str = BAND_USEFUL) -> SecurityEvent:
    """A detected event plus its pending training candidate, as the pipeline
    would leave them, owned by `user_id`."""
    event = SecurityEvent(
        user_id=user_id,
        lab_id="xss_reflected",
        detection_result="detected",
        attack_category="xss",
        severity="high",
        explanation="Reflected XSS: the payload was echoed into the response unescaped.",
        defense_recommendation="Context-encode output; use a template autoescape.",
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    candidate = TrainingExample(
        event_id=event.id,
        instruction="Explain the attack and how to defend against it.",
        input_text="A parameter contained <script>alert(1)</script>.",
        output_text="Reflected XSS. Encode output and enable autoescaping.",
        attack_type="xss",
        severity="high",
        source="sentientai_lab",
        approved=False,
        status=CANDIDATE,
        safe_to_train=False,
        model_prediction="xss",
        provenance="lab_submission",
        dedup_hash=training_service.dedup_hash(
            "Explain the attack and how to defend against it.",
            "A parameter contained <script>alert(1)</script>.",
        ),
        quality_score=80,
        quality_band=band,
    )
    db.add(candidate)
    db.commit()
    db.refresh(candidate)
    return event


# ---------------------------------------------------------------------------
# Access control and scoping
# ---------------------------------------------------------------------------

def test_feedback_is_closed_to_anonymous_visitors(client, db, user):
    event = _event_with_candidate(db, user.id)
    response = client.post(f"/testing/events/{event.id}/feedback", {"verdict": "helpful"})
    assert response.status_code in (303, 401, 403)
    assert db.query(AnalysisFeedback).count() == 0


def test_a_user_can_record_a_verdict_on_their_own_event(auth_client, db, user):
    event = _event_with_candidate(db, user.id)
    response = auth_client.post(
        f"/testing/events/{event.id}/feedback",
        {"verdict": "helpful", "note": "Clear and correct."},
    )
    assert response.status_code == 303
    assert response.headers["location"] == f"/testing/events/{event.id}"

    row = db.query(AnalysisFeedback).filter(
        AnalysisFeedback.event_id == event.id,
        AnalysisFeedback.user_id == user.id,
    ).first()
    assert row is not None
    assert row.verdict == "helpful"
    assert row.note == "Clear and correct."


def test_feedback_on_another_users_event_is_a_404(app, db, user, other_user):
    from tests.conftest import Client

    event = _event_with_candidate(db, user.id)

    intruder = Client(app)
    intruder.login(other_user.username)
    response = intruder.post(f"/testing/events/{event.id}/feedback", {"verdict": "helpful"})
    assert response.status_code == 404
    # Nothing was written on someone else's behalf.
    assert db.query(AnalysisFeedback).count() == 0


def test_an_unknown_verdict_is_refused(auth_client, db, user):
    event = _event_with_candidate(db, user.id)
    response = auth_client.post(
        f"/testing/events/{event.id}/feedback", {"verdict": "spectacular"},
    )
    assert response.status_code == 400
    assert db.query(AnalysisFeedback).count() == 0


# ---------------------------------------------------------------------------
# One verdict per (event, user)
# ---------------------------------------------------------------------------

def test_a_second_verdict_updates_in_place(auth_client, db, user):
    event = _event_with_candidate(db, user.id)
    auth_client.post(f"/testing/events/{event.id}/feedback", {"verdict": "helpful"})
    auth_client.post(f"/testing/events/{event.id}/feedback", {"verdict": "incorrect"})

    rows = db.query(AnalysisFeedback).filter(AnalysisFeedback.event_id == event.id).all()
    assert len(rows) == 1
    assert rows[0].verdict == "incorrect"


# ---------------------------------------------------------------------------
# "Incorrect" is advisory only — it re-triages, it never trains
# ---------------------------------------------------------------------------

def test_incorrect_feedback_downgrades_a_useful_candidate_to_review(auth_client, db, user):
    event = _event_with_candidate(db, user.id, band=BAND_USEFUL)
    auth_client.post(f"/testing/events/{event.id}/feedback", {"verdict": "incorrect"})

    db.expire_all()
    candidate = db.query(TrainingExample).filter(
        TrainingExample.event_id == event.id,
    ).first()
    # Re-triaged down for a human's attention...
    assert candidate.quality_band == BAND_REVIEW
    assert "incorrect" in (candidate.quality_notes or "").lower()
    # ...but still just a candidate. Nothing here makes it trainable.
    assert candidate.is_pending is True
    assert candidate.safe_to_train is False


def test_incorrect_feedback_never_touches_an_approved_candidate(auth_client, db, user, admin):
    event = _event_with_candidate(db, user.id, band=BAND_USEFUL)
    candidate = db.query(TrainingExample).filter(
        TrainingExample.event_id == event.id,
    ).first()
    training_service.approve_example(db, candidate.id, admin.id)

    auth_client.post(f"/testing/events/{event.id}/feedback", {"verdict": "incorrect"})

    db.expire_all()
    candidate = db.query(TrainingExample).filter(
        TrainingExample.event_id == event.id,
    ).first()
    # An approved row is out of the pending pool, so feedback leaves it alone —
    # only a human review can move it now.
    assert candidate.state == "approved"
    assert candidate.safe_to_train is True
    assert candidate.quality_band == BAND_USEFUL


def test_helpful_feedback_leaves_the_candidate_band_untouched(auth_client, db, user):
    event = _event_with_candidate(db, user.id, band=BAND_USEFUL)
    auth_client.post(f"/testing/events/{event.id}/feedback", {"verdict": "helpful"})

    db.expire_all()
    candidate = db.query(TrainingExample).filter(
        TrainingExample.event_id == event.id,
    ).first()
    assert candidate.quality_band == BAND_USEFUL


# ---------------------------------------------------------------------------
# Auditing and UI
# ---------------------------------------------------------------------------

def test_feedback_is_audited(auth_client, db, user):
    event = _event_with_candidate(db, user.id)
    auth_client.post(f"/testing/events/{event.id}/feedback", {"verdict": "unhelpful"})
    types = {
        e.event_type for e in db.query(AuditEvent).filter(
            AuditEvent.event_type == "analysis.feedback",
        ).all()
    }
    assert types == {"analysis.feedback"}


def test_the_event_page_shows_the_feedback_control(auth_client, db, user):
    event = _event_with_candidate(db, user.id)
    body = auth_client.get(f"/testing/events/{event.id}").text
    assert f"/testing/events/{event.id}/feedback" in body
    assert 'name="verdict"' in body
