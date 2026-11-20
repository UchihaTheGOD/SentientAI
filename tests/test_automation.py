"""AI Automation Center: queue, worker, retry, dedup, review, import.

Model note: tests that need a *successful* AI assessment use a stubbed
``classify_log`` (status "ok") inside the automation service module,
because this VM has no GPU, no torch and no weights. The fusion,
incident, dedup and collection steps under test are the real code.
Tests that need the real model-down path use the genuine classifier,
which returns status "unavailable" here. Nothing here claims real
inference works.
"""

from __future__ import annotations


FAKE_THREAT = {
    "source": "cyberllm", "status": "ok",
    "classification": "likely_threat", "model_classification": "likely_threat",
    "confidence": "high",
    "summary": "SSRF probe against cloud metadata endpoint.",
    "indicators": ["169.254.169.254"],
    "reasoning": "The request asks the server to fetch a link-local metadata address.",
    "limitations": [], "recommended_actions": ["Review the incident and block the source."],
    "deterministic_findings": [], "parse_ok": True, "truncated": False,
    "output_tokens": 42, "latency_ms": 5, "raw_output": "{}", "error": None,
}

FAKE_BENIGN = dict(FAKE_THREAT, status="ok", classification="likely_benign",
                   model_classification="likely_benign", confidence="high",
                   summary="Ordinary page view.", indicators=[],
                   reasoning="No suspicious indicators in this request.",
                   recommended_actions=[])

# Mirrors what real classify_log returns for the SSRF metadata probe:
# the model says benign, but cyberllm_rules.screen() fires a
# high-severity metadata-endpoint finding, and fuse's deterministic
# override floors the fused verdict to likely_threat. This is the
# preserved SSRF behavior, and it is how a real fused threat arises
# here (evaluate_rules scores 0 on this text on its own).
FAKE_SSRF_OVERRIDE = dict(
    FAKE_THREAT, classification="likely_benign",
    model_classification="likely_benign",
    summary="Server-side request appears ordinary.",
    indicators=[],
    reasoning="No model-side indicator, but a deterministic finding fired.",
    deterministic_findings=[{
        "rule": "metadata_endpoint", "severity": "high",
        "explanation": "Request targets a cloud metadata endpoint.",
    }],
)

SSRF_EVIDENCE = "GET /fetch?u=http://169.254.169.254/latest/meta-data/ HTTP/1.1"


def _session():
    from app.database import SessionLocal

    return SessionLocal()


def _make_event(session, **overrides):
    from app.services.security_events import log_event

    kwargs = {
        "event_type": "http.200", "category": "benign", "severity": "low",
        "source": "middleware", "route": "/", "method": "GET",
        "http_status": 200, "evidence": "harmless page view",
    }
    kwargs.update(overrides)
    return log_event(session, **kwargs)


def _job_for(session, event_id):
    from app.models.automation import AutomationJob

    return session.query(AutomationJob).filter(
        AutomationJob.event_id == event_id
    ).first()


def _reset_retry(session, job):
    job.next_attempt_at = None
    session.commit()


def test_log_event_auto_enqueues_job(admin):
    from app.models.automation import AutomationJob

    s = _session()
    ev = _make_event(s)
    job = _job_for(s, ev.id)
    assert job is not None
    assert job.status == "pending" and job.attempts == 0
    assert s.query(AutomationJob).filter(AutomationJob.event_id == ev.id).count() == 1
    s.close()


def test_duplicate_enqueue_returns_existing(admin):
    from app.services.automation import enqueue_event

    s = _session()
    ev = _make_event(s)
    first = _job_for(s, ev.id)
    second = enqueue_event(ev.id, db=s)
    assert second.id == first.id
    from app.models.automation import AutomationJob

    assert s.query(AutomationJob).filter(AutomationJob.event_id == ev.id).count() == 1
    s.close()


def test_worker_processes_threat_end_to_end(admin, monkeypatch):
    import app.services.automation as auto

    monkeypatch.setattr(auto, "classify_log", lambda *a, **kw: dict(FAKE_SSRF_OVERRIDE))
    s = _session()
    ev = _make_event(s, evidence=SSRF_EVIDENCE, category="ssrf",
                     severity="high", route="/fetch")
    job = auto.process_one(s)
    # The worker claims the OLDEST due job; the seeded event may not be
    # first if middleware logged requests during fixture login, so
    # process until our job completes.
    guard = 0
    while job is not None and _job_for(s, ev.id).status == "pending" and guard < 50:
        job = auto.process_one(s)
        guard += 1
    done = _job_for(s, ev.id)
    assert done.status == "completed"
    assert done.verdict == "likely_threat"
    assert done.incident_id is not None and done.incident_outcome == "created"
    assert done.training_example_id is not None
    assert done.review_exclusion_reason is None
    assert done.latency_ms is not None and done.latency_ms >= 0
    from app.models.training_example import TrainingExample

    ex = s.query(TrainingExample).filter(
        TrainingExample.id == done.training_example_id).first()
    assert ex is not None and ex.status == "candidate" and not ex.safe_to_train
    s.close()


def test_benign_event_no_incident_no_candidate(admin, monkeypatch):
    import app.services.automation as auto

    monkeypatch.setattr(auto, "classify_log", lambda *a, **kw: dict(FAKE_BENIGN))
    s = _session()
    ev = _make_event(s)
    job = _job_for(s, ev.id)
    out = auto.process_job(s, job)
    assert out.status == "completed"
    assert out.verdict == "likely_benign"
    assert out.incident_id is None and out.incident_outcome == "none"
    assert out.training_example_id is None
    assert out.review_exclusion_reason == "benign_no_incident"
    s.close()


def test_suspicious_event_forced_to_review_incident(admin, monkeypatch):
    import app.services.automation as auto

    monkeypatch.setattr(auto, "classify_log", lambda *a, **kw: dict(FAKE_BENIGN))
    s = _session()
    ev = _make_event(s, event_type="suspicious_input.xss", category="xss",
                     severity="medium", route="/search",
                     evidence="<script>alert(1)</script>")
    job = _job_for(s, ev.id)
    out = auto.process_job(s, job)
    assert out.verdict == "needs_review"  # bridge parity: suspicious forces review
    assert out.incident_id is not None
    s.close()


def test_model_unavailable_retries_then_fails(admin, monkeypatch):
    import app.services.automation as auto

    monkeypatch.setattr(auto, "classify_log", lambda *a, **kw: {
        "source": "cyberllm", "status": "unavailable", "classification": "needs_review",
        "model_classification": None, "confidence": "low", "summary": "",
        "indicators": [], "reasoning": "",
        "limitations": ["CyberLLMv1 unavailable: no model loaded"],
        "recommended_actions": [], "deterministic_findings": [],
        "parse_ok": False, "truncated": False, "output_tokens": 0,
        "latency_ms": 0, "raw_output": "", "error": "no model loaded",
    })
    s = _session()
    ev = _make_event(s, evidence=SSRF_EVIDENCE)
    job = _job_for(s, ev.id)
    for _ in range(3):
        _reset_retry(s, job)
        out = auto.process_one(s)
        assert out is not None
        job = _job_for(s, ev.id)
    assert job.status == "failed"
    assert job.attempts == 3
    assert "unavailable" in (job.error_message or "")
    assert job.incident_id is None and job.training_example_id is None
    # A failed job is not retried automatically again.
    assert auto.process_one(s) is None or _job_for(s, ev.id).status == "failed"
    s.close()


def test_duplicate_incident_protection(admin, monkeypatch):
    import app.services.automation as auto
    from app.models.sentinel_incident import SentinelIncident

    monkeypatch.setattr(auto, "classify_log", lambda *a, **kw: dict(FAKE_THREAT))
    s = _session()
    common = {"event_type": "http.200", "category": "ssrf", "severity": "high",
              "source": "middleware", "route": "/fetch", "method": "GET",
              "http_status": 200, "evidence": SSRF_EVIDENCE,
              "ip_address": "203.0.113.7"}
    ev1 = _make_event(s, **common)
    ev2 = _make_event(s, **common)
    out1 = auto.process_job(s, _job_for(s, ev1.id))
    out2 = auto.process_job(s, _job_for(s, ev2.id))
    assert out1.incident_outcome == "created"
    assert out2.incident_outcome == "linked"
    assert out2.incident_id == out1.incident_id
    assert s.query(SentinelIncident).filter(
        SentinelIncident.log_text.contains("169.254.169.254")).count() == 1
    s.close()


def test_worker_restart_recovery(admin):
    import app.services.automation as auto

    s = _session()
    ev = _make_event(s)
    job = _job_for(s, ev.id)
    job.status = "processing"
    s.commit()
    assert auto.reset_stale_processing(s) >= 1
    assert _job_for(s, ev.id).status == "pending"
    s.close()


def test_job_persists_across_sessions(admin):
    s = _session()
    ev = _make_event(s)
    job_id = _job_for(s, ev.id).id
    s.close()
    s2 = _session()
    from app.models.automation import AutomationJob

    row = s2.query(AutomationJob).filter(AutomationJob.id == job_id).first()
    assert row is not None and row.event_id == ev.id and row.status == "pending"
    s2.close()


def test_candidate_requires_human_approval(admin, monkeypatch):
    import app.services.automation as auto
    from app.services.training import approve_example, get_approved_examples

    monkeypatch.setattr(auto, "classify_log", lambda *a, **kw: dict(FAKE_THREAT))
    s = _session()
    ev = _make_event(s, evidence=SSRF_EVIDENCE, category="ssrf", severity="high")
    out = auto.process_job(s, _job_for(s, ev.id))
    ex_id = out.training_example_id
    assert ex_id is not None
    approved_ids = {ex.id for ex in get_approved_examples(s)}
    assert ex_id not in approved_ids
    reviewed = approve_example(s, ex_id, admin.id, note="verified by test")
    assert reviewed is not None and reviewed.status == "approved"
    approved_ids = {ex.id for ex in get_approved_examples(s)}
    assert ex_id in approved_ids
    s.close()


def test_dashboard_stats_and_job_detail(admin_client, admin, monkeypatch):
    import app.services.automation as auto

    monkeypatch.setattr(auto, "classify_log", lambda *a, **kw: dict(FAKE_SSRF_OVERRIDE))
    before = admin_client.get("/api/security/automation/stats")
    assert before.status_code == 200
    base = before.json()
    s = _session()
    ev = _make_event(s, evidence=SSRF_EVIDENCE, category="ssrf", severity="high")
    auto.process_job(s, _job_for(s, ev.id))
    failed_ev = _make_event(s)
    failed_job = _job_for(s, failed_ev.id)
    failed_job.status = "failed"
    failed_job.attempts = 3
    s.commit()
    job_id = _job_for(s, ev.id).id
    s.close()
    after = admin_client.get("/api/security/automation/stats").json()
    assert after["completed"] == base["completed"] + 1
    assert after["likely_threats"] == base["likely_threats"] + 1
    assert after["incidents_created"] == base["incidents_created"] + 1
    assert after["candidates_generated"] == base["candidates_generated"] + 1
    assert after["failed"] == base["failed"] + 1
    assert after["retry_queue"] >= after["failed"]
    assert after["avg_latency_ms"] is not None
    assert after["model"]["ready"] in (True, False)
    detail = admin_client.get(f"/api/security/automation/jobs/{job_id}")
    assert detail.status_code == 200
    assert detail.json()["event"]["id"] == ev.id
    page = admin_client.get("/admin/automation")
    assert page.status_code == 200
    assert "AI Automation Center" in page.text


def test_api_requires_admin(client):
    assert client.get("/api/security/automation/stats").status_code == 401
    assert client.get("/admin/automation").status_code in (401, 303, 307)


def test_retry_failed_and_backfill_endpoints(admin_client, admin):
    s = _session()
    ev = _make_event(s)
    ev_id = ev.id
    job = _job_for(s, ev.id)
    job.status = "failed"
    job.attempts = 3
    s.commit()
    job_id = job.id
    s.close()
    res = admin_client._client.post("/api/security/automation/retry-failed", headers={"X-CSRF-Token": admin_client._csrf()})
    assert res.status_code == 200 and res.json()["retried"] >= 1
    s = _session()
    from app.models.automation import AutomationJob

    row = s.query(AutomationJob).filter_by(id=job_id).first()
    assert row.status == "pending" and row.attempts == 0
    # Backfill: remove the job, then backfill must recreate it; a second
    # backfill must not duplicate it.
    s.delete(row)
    s.commit()
    s.close()
    first = admin_client._client.post("/api/security/automation/backfill", headers={"X-CSRF-Token": admin_client._csrf()})
    assert first.status_code == 200 and first.json()["created"] >= 1
    second = admin_client._client.post("/api/security/automation/backfill", headers={"X-CSRF-Token": admin_client._csrf()})
    assert second.status_code == 200
    s = _session()
    from app.models.automation import AutomationJob

    assert s.query(AutomationJob).filter(AutomationJob.event_id == ev_id).count() == 1
    s.close()


def test_worker_start_pause_via_api(admin_client):
    import app.services.automation as auto

    try:
        res = admin_client._client.post("/api/security/automation/start", headers={"X-CSRF-Token": admin_client._csrf()})
        assert res.status_code == 200 and res.json()["enabled"] is True
        s = _session()
        state = auto.worker_state(s)
        s.close()
        assert state["state"] in ("running", "stale")
        res = admin_client._client.post("/api/security/automation/pause", headers={"X-CSRF-Token": admin_client._csrf()})
        assert res.status_code == 200 and res.json()["enabled"] is False
    finally:
        auto.stop_worker()


def test_scanner_import_validation_and_dedup(admin_client, admin):
    from app.models.attact_assessment import SecurityEvent
    from app.models.automation import AutomationJob

    payload = {
        "scan_id": "scan-auto-test-1",
        "target": "http://127.0.0.1:9/",
        "scanned_at": "2026-10-31T12:00:00",
        "findings": [
            {"name": "Missing security header", "category": "headers_tls",
             "severity": "Medium", "confidence": "high", "status": "suspected",
             "explanation": "X-Content-Type-Options missing.",
             "evidence": "header absent"},
            {"name": "Sensitive file exposed", "category": "sensitive_files",
             "severity": "High", "confidence": "medium", "status": "suspected",
             "explanation": "/.env reachable.", "evidence": "HTTP 200"},
        ],
    }
    res = admin_client._client.post("/api/security/automation/scanner-import", json=payload, headers={"X-CSRF-Token": admin_client._csrf()})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["imported"] == 2 and len(body["event_ids"]) == 2
    s = _session()
    events = s.query(SecurityEvent).filter(
        SecurityEvent.id.in_(body["event_ids"])).all()
    assert len(events) == 2
    assert all(e.source == "desktop_scanner" for e in events)
    assert all("scan-auto-test-1" in (e.meta_json or "") for e in events)
    jobs = s.query(AutomationJob).filter(
        AutomationJob.event_id.in_(body["event_ids"])).all()
    assert len(jobs) == 2 and all(j.status == "pending" for j in jobs)
    s.close()
    dup = admin_client._client.post("/api/security/automation/scanner-import", json=payload, headers={"X-CSRF-Token": admin_client._csrf()})
    assert dup.status_code == 409
    bad = dict(payload, scan_id="scan-auto-test-2")
    bad["findings"] = [dict(payload["findings"][0], severity="catastrophic")]
    s = _session()
    before = s.query(SecurityEvent).filter(
        SecurityEvent.source == "desktop_scanner").count()
    s.close()
    bad_res = admin_client._client.post("/api/security/automation/scanner-import", json=bad, headers={"X-CSRF-Token": admin_client._csrf()})
    assert bad_res.status_code == 422
    s = _session()
    after = s.query(SecurityEvent).filter(
        SecurityEvent.source == "desktop_scanner").count()
    s.close()
    assert after == before  # no partial import


def test_sentinel_analyze_collects_eligible(admin_client, admin, monkeypatch):
    import app.services.classifier as clf

    monkeypatch.setattr(clf, "classify_log", lambda *a, **kw: dict(FAKE_THREAT))
    res = admin_client._client.post("/api/sentinel/analyze", json={
        "log_text": SSRF_EVIDENCE, "create_incident": True,
    }, headers={"X-CSRF-Token": admin_client._csrf()})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["incident_id"] is not None
    assert body["training_example_id"] is not None
    assert body["training_collection"] == "created"
    # Benign pasted log: no incident, no candidate, explicit reason.
    monkeypatch.setattr(clf, "classify_log", lambda *a, **kw: dict(FAKE_BENIGN))
    res2 = admin_client._client.post("/api/sentinel/analyze", json={
        "log_text": "GET / HTTP/1.1 200 OK", "create_incident": True,
    }, headers={"X-CSRF-Token": admin_client._csrf()})
    assert res2.status_code == 200
    assert res2.json()["training_example_id"] is None
    assert res2.json()["training_collection"] == "not_eligible"


def test_sentinel_analyze_unparseable_excluded(admin_client, admin):
    # Real classifier, no model in this VM: rules-only fusion still
    # creates the incident, but the unparseable output must not become
    # a training candidate.
    res = admin_client._client.post("/api/sentinel/analyze", json={
        "log_text": SSRF_EVIDENCE, "create_incident": True,
    }, headers={"X-CSRF-Token": admin_client._csrf()})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["incident_id"] is not None
    assert body["training_example_id"] is None
    assert body["training_collection"] == "model_output_unparseable"


def test_collection_failure_records_reason_and_keeps_link(admin, monkeypatch):
    """R1: a failed collection must be explicit and must not drop the link.

    The failure is driven through the REAL collect_from_incident by
    breaking its dedup step, so collect's own except -> rollback ->
    None path runs exactly as in production. Before the fix this test
    failed twice over: the exclusion stayed None, and the rollback
    discarded the pending event.incident_id assignment.
    """
    import app.services.automation as auto
    import app.services.training as training_service
    from app.models.attact_assessment import SecurityEvent
    from app.models.training_example import TrainingExample

    monkeypatch.setattr(auto, "classify_log", lambda *a, **kw: dict(FAKE_THREAT))

    def _boom(*a, **kw):
        raise RuntimeError("dedup unavailable")

    monkeypatch.setattr(training_service, "dedup_hash", _boom)
    s = _session()
    ev = _make_event(s, evidence=SSRF_EVIDENCE, category="ssrf", severity="high")
    before_examples = s.query(TrainingExample).count()
    out = auto.process_job(s, _job_for(s, ev.id))
    assert out.status == "completed"
    assert out.incident_id is not None and out.incident_outcome == "created"
    assert out.training_example_id is None
    assert out.review_exclusion_reason == "collection_failed"
    fresh = s.query(SecurityEvent).filter(SecurityEvent.id == ev.id).first()
    assert fresh.incident_id == out.incident_id
    assert s.query(TrainingExample).count() == before_examples
    s.close()


def test_crash_recovery_reuses_orphan_incident(admin, monkeypatch):
    """R2: a crash between incident commit and link persistence must not duplicate.

    The orphan incident is aged past the 10-minute dedup window, so
    only the window-free per-event lookup can save it. The test proves
    the window genuinely missed by asserting _find_recent_duplicate
    returns None for the same key.
    """
    import json
    from datetime import datetime, timedelta, timezone

    import app.services.automation as auto
    from app.models.sentinel_incident import SentinelIncident
    from app.services.incident_service import create_incident
    from app.services.sentinel_bridge import _dedup_key, _event_log_text

    monkeypatch.setattr(auto, "classify_log", lambda *a, **kw: dict(FAKE_THREAT))
    s = _session()
    ev = _make_event(s, evidence=SSRF_EVIDENCE, category="ssrf", severity="high",
                     ip_address="203.0.113.9")
    log_text = _event_log_text(ev)
    meta = json.dumps({
        "dedup_key": _dedup_key(ev.ip_address, log_text),
        "source_event_id": ev.id,
        "triggered_by": "automation",
    })
    orphan = create_incident(
        s, log_text=log_text, ip_address=ev.ip_address,
        fused={"fused_score": 90, "fused_verdict": "likely_threat",
               "rules": {"evidence": []}},
        classification=None, containment_meta=meta,
    )
    orphan.created_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=20)
    s.commit()
    assert ev.incident_id is None  # link lost in the simulated crash
    assert auto._find_recent_duplicate(s, _dedup_key(ev.ip_address, log_text)) is None
    before = s.query(SentinelIncident).count()
    out = auto.process_job(s, _job_for(s, ev.id))
    assert s.query(SentinelIncident).count() == before  # no second incident
    assert out.incident_id == orphan.id and out.incident_outcome == "linked"
    assert out.training_example_id is not None  # candidacy from the orphan
    from app.models.attact_assessment import SecurityEvent
    fresh = s.query(SecurityEvent).filter(SecurityEvent.id == ev.id).first()
    assert fresh.incident_id == orphan.id
    s.close()


def test_duplicate_processing_reuses_linked_incident(admin, monkeypatch):
    """Reprocessing an already-linked event must not create a second incident."""
    import app.services.automation as auto
    from app.models.sentinel_incident import SentinelIncident

    monkeypatch.setattr(auto, "classify_log", lambda *a, **kw: dict(FAKE_THREAT))
    s = _session()
    ev = _make_event(s, evidence=SSRF_EVIDENCE, category="ssrf", severity="high")
    first = auto.process_job(s, _job_for(s, ev.id))
    assert first.incident_outcome == "created"
    count = s.query(SentinelIncident).count()
    job = _job_for(s, ev.id)
    job.status = "pending"
    job.attempts = 0
    s.commit()
    second = auto.process_job(s, _job_for(s, ev.id))
    assert second.incident_outcome == "linked"
    assert second.incident_id == first.incident_id
    assert second.training_example_id == first.training_example_id
    assert s.query(SentinelIncident).count() == count
    s.close()
