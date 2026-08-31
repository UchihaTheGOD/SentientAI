"""The private testing area, and the labs it hosts.

Two separate claims are checked. First, that `/testing` is closed to anyone who
is not signed in — enforced by the `require_lab_access` dependency, so a route
added without it would show up here as a passing anonymous request. Second, that
the labs still behave: a benign payload gets a result page, a critical payload
is blocked and terminates the session, and a session belongs to exactly one
account.
"""
from __future__ import annotations

import pytest

from app.models.lab_session import LabSession
from app.models.security_event import SecurityEvent
from app.models.training_example import TrainingExample
from app.services.detection import detect

TESTING_PATHS = [
    "/testing",
    "/testing/labs",
    "/testing/labs/sqli",
    "/testing/sessions",
    "/testing/events",
    "/testing/blocked",
    "/testing/sentinel",
    "/testing/knowledge",
    "/testing/training",
]


def _latest_session(db, user_id: int) -> LabSession:
    return (
        db.query(LabSession)
        .filter(LabSession.user_id == user_id)
        .order_by(LabSession.id.desc())
        .first()
    )


# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", TESTING_PATHS)
def test_testing_area_is_closed_to_anonymous_visitors(client, path):
    response = client.get(path)
    assert response.status_code in (303, 401, 403), f"{path} -> {response.status_code}"
    if response.status_code == 303:
        assert response.headers["location"].startswith("/login")


def test_lab_submit_is_closed_to_anonymous_visitors(client):
    response = client.post("/testing/labs/sqli/submit", {"payload": "alice"})
    assert response.status_code in (303, 401, 403)


def test_suspended_account_loses_lab_access(client, db, user):
    assert client.login(user.username).status_code == 303
    assert client.get("/testing").status_code == 200

    from app.models.user import User
    row = db.query(User).filter(User.id == user.id).first()
    row.is_suspended = True
    db.commit()

    # Still holding a valid cookie, but the account may no longer act.
    response = client.get("/testing")
    assert response.status_code == 403


def test_signed_in_user_reaches_the_testing_overview(auth_client):
    response = auth_client.get("/testing")
    assert response.status_code == 200


def test_unknown_lab_is_a_404(auth_client):
    assert auth_client.get("/testing/labs/not-a-lab").status_code == 404


# ---------------------------------------------------------------------------
# Analysis layer pages (sentinel / knowledge / training) — read-only, scoped
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/testing/sentinel", "/testing/knowledge", "/testing/training"])
def test_analysis_pages_load_for_a_signed_in_user(auth_client, path):
    assert auth_client.get(path).status_code == 200


def test_sentinel_page_states_the_local_analyzer_when_no_endpoint(auth_client):
    # conftest sets CYBERLLM_API_URL="", so the honest state is local-analyzer,
    # not a served neural model. The page must not claim otherwise.
    body = auth_client.get("/testing/sentinel").text.lower()
    assert "local" in body
    assert "detection engine" in body


def test_knowledge_page_shows_only_the_owners_candidates(app, db, user, other_user):
    from tests.conftest import Client

    owner = Client(app)
    owner.login(user.username)
    owner.get("/testing/labs/xss_reflected")
    session = _latest_session(db, user.id)
    owner.post("/testing/labs/xss_reflected/submit", {
        "payload": "<script>alert(1)</script>", "session_id": session.session_id,
    })
    event = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.user_id == user.id)
        .order_by(SecurityEvent.id.desc())
        .first()
    )

    # The owner sees a link to their own event; a second account does not.
    link = f'/testing/events/{event.id}"'
    assert link in owner.get("/testing/knowledge").text

    intruder = Client(app)
    intruder.login(other_user.username)
    assert link not in intruder.get("/testing/knowledge").text


def test_training_page_hides_admin_actions_from_ordinary_users(auth_client, admin_client):
    # The dataset counts are shared, but the promotion/export controls are not.
    assert "/admin/training" not in auth_client.get("/testing/training").text
    assert "/admin/training" in admin_client.get("/testing/training").text


# ---------------------------------------------------------------------------
# Lab behaviour (regression — these flows existed before the redesign)
# ---------------------------------------------------------------------------

def test_benign_submission_returns_a_result_page(auth_client, db, user):
    assert auth_client.get("/testing/labs/sqli").status_code == 200
    session = _latest_session(db, user.id)
    assert session is not None and session.is_active

    response = auth_client.post("/testing/labs/sqli/submit", {
        "payload": "alice", "session_id": session.session_id,
    })
    assert response.status_code == 200

    db.expire_all()
    session = _latest_session(db, user.id)
    assert session.attack_count == 1
    assert session.is_active


def test_critical_payload_blocks_and_terminates_the_session(auth_client, db, user):
    auth_client.get("/testing/labs/sqli")
    session = _latest_session(db, user.id)

    response = auth_client.post("/testing/labs/sqli/submit", {
        "payload": "alice; whoami", "session_id": session.session_id,
    })
    # A block must end the interaction, never render a result page.
    assert response.status_code == 303
    assert response.headers["location"] == f"/testing/session-ended/{session.session_id}"

    db.expire_all()
    session = _latest_session(db, user.id)
    assert session.status == "terminated"
    assert not session.is_active
    assert session.blocked_count == 1
    assert "Severity: critical" in (session.termination_reason or "")

    ended = auth_client.follow(response)
    assert ended.status_code == 200


def test_a_terminated_session_refuses_further_submissions(auth_client, db, user):
    auth_client.get("/testing/labs/sqli")
    session = _latest_session(db, user.id)
    session_id = session.session_id

    auth_client.post("/testing/labs/sqli/submit", {
        "payload": "; cat /etc/passwd", "session_id": session_id,
    })
    again = auth_client.post("/testing/labs/sqli/submit", {
        "payload": "alice", "session_id": session_id,
    })
    assert again.status_code == 303
    assert again.headers["location"] == f"/testing/session-ended/{session_id}"


def test_submission_records_an_event_and_only_a_candidate_example(auth_client, db, user):
    auth_client.get("/testing/labs/xss_reflected")
    session = _latest_session(db, user.id)
    auth_client.post("/testing/labs/xss_reflected/submit", {
        "payload": "<script>alert(1)</script>", "session_id": session.session_id,
    })

    event = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.user_id == user.id)
        .order_by(SecurityEvent.id.desc())
        .first()
    )
    assert event is not None
    assert event.detection_result == "detected"
    # The stored payload is truncated and never re-rendered as markup.
    assert len(event.sanitized_payload) <= 500

    example = (
        db.query(TrainingExample)
        .filter(TrainingExample.event_id == event.id)
        .first()
    )
    assert example is not None
    # Nothing a user typed may arrive pre-approved.
    assert example.status == "candidate"
    assert example.approved is False
    assert example.safe_to_train is False
    assert example.is_trainable is False


def test_one_users_session_is_invisible_to_another(app, db, user, other_user):
    from tests.conftest import Client

    owner = Client(app)
    owner.login(user.username)
    owner.get("/testing/labs/sqli")
    session = _latest_session(db, user.id)

    intruder = Client(app)
    intruder.login(other_user.username)
    assert intruder.get(f"/testing/sessions/{session.session_id}").status_code == 404
    assert intruder.get(f"/testing/session-ended/{session.session_id}").status_code == 404

    # And a submission quoting someone else's session id must not touch it.
    intruder.post("/testing/labs/sqli/submit", {
        "payload": "alice", "session_id": session.session_id,
    })
    db.expire_all()
    assert _latest_session(db, user.id).attack_count in (0, None)


def test_one_users_event_is_invisible_to_another(app, db, user, other_user):
    from tests.conftest import Client

    owner = Client(app)
    owner.login(user.username)
    owner.get("/testing/labs/sqli")
    session = _latest_session(db, user.id)
    owner.post("/testing/labs/sqli/submit", {
        "payload": "alice", "session_id": session.session_id,
    })
    event = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.user_id == user.id)
        .order_by(SecurityEvent.id.desc())
        .first()
    )

    intruder = Client(app)
    intruder.login(other_user.username)
    assert intruder.get(f"/testing/events/{event.id}").status_code == 404


# ---------------------------------------------------------------------------
# Detection engine — the severity rule the brief requires to stay intact
# ---------------------------------------------------------------------------

def test_critical_severity_always_blocks():
    result = detect("; whoami", "sqli")
    assert result.detected
    assert result.severity == "critical"
    assert result.should_block is True


def test_severity_is_never_downgraded_by_a_later_match():
    # A payload that trips both a medium (xss) and a critical (command
    # injection) rule must be classified by the worse of the two.
    result = detect("<script>x</script>; whoami", "xss")
    assert result.severity == "critical"
    assert result.should_block is True


def test_non_critical_detection_does_not_block():
    result = detect("' OR 1=1 --", "sqli")
    assert result.detected
    assert result.severity == "high"
    assert result.should_block is False


def test_benign_input_is_not_flagged():
    result = detect("alice", "sqli")
    assert result.detected is False
    assert result.should_block is False
