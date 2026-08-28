"""Lab session regression — the flow the old `test_phase2.py` script covered.

That script needed a running server, hardcoded admin credentials and sent no
CSRF token, so it could no longer pass. The behaviour it checked is worth
keeping, so it lives here instead, in-process against the test database:

* visiting a lab opens a session, and the session id is embedded in the form;
* a benign payload is recorded as not detected and the session stays open;
* a medium-severity payload is detected but does *not* terminate the session;
* a critical payload terminates it, and further submissions dead-end;
* one user's sessions and events are invisible to another.

The labs themselves are unchanged — these tests exist so a future edit to the
testing area cannot quietly break them.
"""
from __future__ import annotations

import re

from app.models.lab_session import LabSession
from app.models.security_event import SecurityEvent

BENIGN = "hello world"
XSS = "<script>alert(1)</script>"
CRITICAL = "test; whoami"

_SESSION_ID_RE = re.compile(r'name="session_id"\s+value="([a-f0-9]+)"')


def _open_session(client, lab_id: str) -> str:
    """Visit a lab and return the session id its form carries."""
    page = client.get(f"/testing/labs/{lab_id}")
    assert page.status_code == 200, page.status_code
    match = _SESSION_ID_RE.search(page.text)
    assert match, f"no session_id in the {lab_id} form"
    return match.group(1)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def test_the_labs_are_still_registered(auth_client):
    page = auth_client.get("/testing/labs")
    assert page.status_code == 200
    for lab_id in ("sqli", "xss_stored", "xss_reflected"):
        assert lab_id in page.text, lab_id


def test_an_unknown_lab_is_a_404(auth_client):
    assert auth_client.get("/testing/labs/no-such-lab").status_code == 404


def test_submitting_to_an_unknown_lab_is_a_404(auth_client):
    assert auth_client.post(
        "/testing/labs/no-such-lab/submit", {"payload": BENIGN},
    ).status_code == 404


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------

def test_visiting_a_lab_opens_a_session(auth_client, db, user):
    session_id = _open_session(auth_client, "xss_stored")
    row = db.query(LabSession).filter(LabSession.session_id == session_id).first()
    assert row is not None
    assert row.user_id == user.id
    assert row.lab_id == "xss_stored"
    assert row.is_active is True


def test_a_benign_payload_is_recorded_and_leaves_the_session_open(auth_client, db):
    session_id = _open_session(auth_client, "xss_stored")
    response = auth_client.post("/testing/labs/xss_stored/submit", {
        "payload": BENIGN, "session_id": session_id,
    })
    assert response.status_code == 200
    assert "NOT DETECTED" in response.text

    db.expire_all()
    row = db.query(LabSession).filter(LabSession.session_id == session_id).first()
    assert row.is_active is True
    assert row.attack_count == 1
    assert row.detected_count == 0
    assert row.blocked_count == 0


def test_a_medium_severity_payload_is_detected_but_does_not_terminate(auth_client, db):
    session_id = _open_session(auth_client, "xss_stored")
    response = auth_client.post("/testing/labs/xss_stored/submit", {
        "payload": XSS, "session_id": session_id,
    })
    # Detected, and the session survives: only a critical finding ends it.
    assert response.status_code == 200
    assert "session-ended" not in str(response.headers.get("location", ""))

    db.expire_all()
    row = db.query(LabSession).filter(LabSession.session_id == session_id).first()
    assert row.detected_count == 1
    assert row.blocked_count == 0
    assert row.is_active is True


def test_a_critical_payload_terminates_the_session(auth_client, db):
    session_id = _open_session(auth_client, "sqli")
    response = auth_client.post("/testing/labs/sqli/submit", {
        "payload": CRITICAL, "session_id": session_id,
    })
    assert response.status_code == 303
    assert response.headers["location"] == f"/testing/session-ended/{session_id}"

    db.expire_all()
    row = db.query(LabSession).filter(LabSession.session_id == session_id).first()
    assert row.is_active is False
    assert row.status == "terminated"
    assert row.ended_at is not None
    assert row.blocked_count == 1
    assert "Critical payload detected" in row.termination_reason

    event = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.session_id == session_id)
        .order_by(SecurityEvent.id.desc())
        .first()
    )
    assert event.blocked is True
    assert event.severity == "critical"


def test_a_terminated_session_refuses_further_submissions(auth_client, db):
    session_id = _open_session(auth_client, "sqli")
    auth_client.post("/testing/labs/sqli/submit", {
        "payload": CRITICAL, "session_id": session_id,
    })

    followup = auth_client.post("/testing/labs/sqli/submit", {
        "payload": BENIGN, "session_id": session_id,
    })
    assert followup.status_code == 303
    assert followup.headers["location"] == f"/testing/session-ended/{session_id}"

    db.expire_all()
    row = db.query(LabSession).filter(LabSession.session_id == session_id).first()
    # The dead-end is real: the second payload was never analysed.
    assert row.attack_count == 1


def test_the_session_ended_page_explains_what_happened(auth_client, db):
    session_id = _open_session(auth_client, "sqli")
    auth_client.post("/testing/labs/sqli/submit", {
        "payload": CRITICAL, "session_id": session_id,
    })

    page = auth_client.get(f"/testing/session-ended/{session_id}")
    assert page.status_code == 200
    assert "Critical payload detected" in page.text
    assert f"/testing/sessions/{session_id}" in page.text


def test_the_timeline_shows_the_session_and_its_events(auth_client, db):
    session_id = _open_session(auth_client, "xss_stored")
    auth_client.post("/testing/labs/xss_stored/submit", {
        "payload": XSS, "session_id": session_id,
    })

    page = auth_client.get(f"/testing/sessions/{session_id}")
    assert page.status_code == 200
    assert session_id in page.text


# ---------------------------------------------------------------------------
# One user's telemetry is their own
# ---------------------------------------------------------------------------

def test_a_session_id_from_another_account_is_not_adopted(auth_client, other_client, db):
    """Posting someone else's session id must not write into their session."""
    victim_session = _open_session(other_client, "xss_stored")

    response = auth_client.post("/testing/labs/xss_stored/submit", {
        "payload": XSS, "session_id": victim_session,
    })
    assert response.status_code == 200

    db.expire_all()
    row = db.query(LabSession).filter(LabSession.session_id == victim_session).first()
    # The lookup is scoped by user_id, so the foreign id resolves to nothing and
    # the submission is recorded without a session rather than against theirs.
    assert row.attack_count in (0, None)
    assert row.detected_count in (0, None)


def test_another_users_session_timeline_is_not_readable(auth_client, other_client):
    victim_session = _open_session(other_client, "sqli")
    response = auth_client.get(f"/testing/sessions/{victim_session}")
    assert response.status_code == 404


def test_the_events_list_only_shows_your_own(auth_client, other_client, db, user):
    mine = _open_session(auth_client, "xss_stored")
    auth_client.post("/testing/labs/xss_stored/submit", {
        "payload": XSS, "session_id": mine,
    })
    theirs = _open_session(other_client, "sqli")
    other_client.post("/testing/labs/sqli/submit", {
        "payload": "' OR 1=1 --", "session_id": theirs,
    })

    page = auth_client.get("/testing/events")
    assert page.status_code == 200

    my_event_ids = {
        e.id for e in db.query(SecurityEvent).filter(SecurityEvent.user_id == user.id).all()
    }
    their_event_ids = {
        e.id for e in db.query(SecurityEvent).filter(SecurityEvent.user_id != user.id).all()
    }
    assert my_event_ids and their_event_ids
    linked = {int(m) for m in re.findall(r"/testing/events/(\d+)", page.text)}
    assert linked & my_event_ids
    assert not (linked & their_event_ids)


def test_another_users_event_detail_is_not_readable(auth_client, other_client, db, other_user):
    theirs = _open_session(other_client, "sqli")
    other_client.post("/testing/labs/sqli/submit", {
        "payload": "' OR 1=1 --", "session_id": theirs,
    })
    event = db.query(SecurityEvent).filter(SecurityEvent.user_id == other_user.id).first()
    assert event is not None
    assert auth_client.get(f"/testing/events/{event.id}").status_code == 404


# ---------------------------------------------------------------------------
# The labs stay sandboxed
# ---------------------------------------------------------------------------

def test_the_sqli_lab_never_touches_the_real_database(auth_client, db, user, other_user):
    """The lab answers from an in-memory table, so a tautology cannot enumerate
    real accounts."""
    session_id = _open_session(auth_client, "sqli")
    response = auth_client.post("/testing/labs/sqli/submit", {
        "payload": "' OR 1=1 --", "session_id": session_id,
    })
    assert response.status_code == 200
    # The tautology "succeeds" — against the fixture table, not the real one.
    assert "alice@example.com" in response.text
    # No real account is reachable. `user`'s own name is in the page chrome, so
    # the account checked here is another one entirely, plus both e-mails: the
    # site never renders those, and the lab must not be the first to do it.
    assert other_user.username not in response.text
    assert user.email not in response.text
    assert other_user.email not in response.text
