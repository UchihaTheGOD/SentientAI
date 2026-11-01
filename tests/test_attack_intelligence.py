"""Stage 5 attack-intelligence tests: assembly, incident application,
and the create_incident intelligence path. MITRE assertions skip
cleanly when the dataset was never imported."""
from types import SimpleNamespace

import pytest

from app.models.sentinel_incident import SentinelIncident
from app.services.attack_intelligence import (
    apply_to_incident,
    build_intelligence,
    incident_intelligence_dict,
    job_assessment_intelligence,
)
from app.services.incident_service import create_incident
from app.services.mitre_attack import MANIFEST_PATH, MitreAttack


def mitre_or_skip():
    try:
        return MitreAttack.load_default()
    except Exception:
        pytest.skip("MITRE dataset not imported (run scripts/import_mitre.py)")


def _blank_incident():
    fields = ["attack_category", "attack_type", "attack_subtype",
              "classification_confidence", "classification_evidence",
              "attack_outcome", "mitre_tactic", "mitre_technique_id",
              "mitre_technique_name", "mitre_subtechnique_id",
              "mitre_subtechnique_name", "mitre_mapping_confidence",
              "mitre_mapping_rationale", "mitre_dataset_version",
              "model_version", "adapter_version", "analysis_timestamp",
              "review_status"]
    return SimpleNamespace(**{f: None for f in fields})


def test_build_sql_injection_primary_no_mitre():
    intel = build_intelligence("id=1 UNION SELECT password FROM users--", mitre=False)
    assert intel["attack_category"] == "web_attack"
    assert intel["attack_type"] == "sql_injection"
    assert intel["attack_outcome"] == "attempted_or_detected"
    assert intel["mitre_technique_id"] is None
    assert intel["mitre_subtechnique_id"] is None
    assert intel["finding_count"] >= 1
    if MANIFEST_PATH.exists():
        assert intel["mitre_dataset_version"] == "20.0"


def test_build_web_shell_mitre_split():
    m = mitre_or_skip()
    intel = build_intelligence("GET /uploads/c99.php?cmd=id", mitre=m)
    assert intel["attack_type"] == "web_shell_indicator"
    assert intel["mitre_technique_id"] == "T1505"
    assert intel["mitre_subtechnique_id"] == "T1505.003"
    assert intel["mitre_subtechnique_name"] == "Web Shell"
    assert intel["mitre_tactic"] == "Persistence"
    assert intel["mitre_mapping_confidence"] == "high"


def test_build_benign_and_empty_never_raise():
    intel = build_intelligence("GET /blog/hello-world 200", mitre=False)
    assert intel["attack_type"] is None
    assert intel["attack_outcome"] == "no_indicator"
    assert intel["mitre_technique_id"] is None
    assert build_intelligence("", mitre=False)["attack_outcome"] == "no_indicator"
    assert build_intelligence(None, mitre=False)["attack_outcome"] == "no_indicator"


def test_auth_attempts_become_fallback_mitre():
    m = mitre_or_skip()
    attempts = [{"username": "alice", "success": False}] * 8
    intel = build_intelligence("failed login", auth_attempts=attempts, mitre=m)
    assert any(f["attack_type"] == "password_guessing" for f in intel["findings"])
    assert intel["mitre_technique_id"] == "T1110"
    assert intel["mitre_subtechnique_id"] == "T1110.001"


def test_rules_primary_kept_when_auth_fallback_supplies_mitre():
    m = mitre_or_skip()
    attempts = [{"username": "alice", "success": False}] * 8
    intel = build_intelligence("id=1 UNION SELECT 1--", auth_attempts=attempts, mitre=m)
    assert intel["attack_type"] == "sql_injection"
    assert intel["mitre_subtechnique_id"] == "T1110.001"
    assert "password-guessing" in (intel["mitre_mapping_rationale"] or "")


def test_joined_text_does_not_false_positive_on_pipe_separator():
    # The worker's log text joins parts with " | "; a part starting
    # with "id=" must not trip the command-injection pipe pattern.
    joined = ("http.200 | category=web_attack | route=/search | method=GET"
              " | id=1 UNION SELECT password FROM users--")
    intel = build_intelligence(joined, joined=True, mitre=False)
    assert intel["attack_type"] == "sql_injection"
    assert not any(f["attack_type"] == "command_injection" for f in intel["findings"])
    # Raw text keeps its pipe semantics: a genuine piped command flags.
    raw = build_intelligence("q=test | id", mitre=False)
    assert any(f["attack_type"] == "command_injection" for f in raw["findings"])


def test_apply_to_incident_no_overwrite_without_force():
    intel = build_intelligence("GET /uploads/c99.php?cmd=id", mitre=False)
    inc = _blank_incident()
    assert apply_to_incident(inc, intel) is True
    assert inc.attack_type == "web_shell_indicator"
    assert inc.review_status == "unreviewed"
    inc.attack_type = "tampered"
    assert apply_to_incident(inc, intel) is False
    assert inc.attack_type == "tampered"
    assert apply_to_incident(inc, intel, force=True) is True
    assert inc.attack_type == "web_shell_indicator"


def test_job_assessment_intelligence_caps_findings():
    intel = {"attack_category": "web_attack", "attack_type": "sql_injection",
             "attack_subtype": None, "classification_confidence": "high",
             "attack_outcome": "attempted_or_detected",
             "mitre_technique_id": None, "mitre_subtechnique_id": None,
             "mitre_technique_name": None, "mitre_subtechnique_name": None,
             "mitre_dataset_version": "20.0",
             "findings": [{"attack_type": f"f{i}"} for i in range(8)]}
    capped = job_assessment_intelligence(intel)
    assert len(capped["findings"]) == 6
    assert capped["finding_count"] == 8
    assert capped["findings_capped"] is True


def test_worker_records_intelligence_on_job_and_incident(admin, monkeypatch):
    """End-to-end through the real worker: verdict comes from the model
    path, intelligence rides alongside and never alters it."""
    import json

    import app.services.automation as auto
    from app.database import SessionLocal
    from app.models.automation import AutomationJob
    from app.models.sentinel_incident import SentinelIncident
    from app.services.security_events import log_event

    monkeypatch.setattr(auto, "classify_log", lambda *a, **kw: {
        "source": "cyberllm", "status": "ok",
        "classification": "likely_threat", "model_classification": "likely_threat",
        "confidence": "high", "summary": "SQL injection attempt.",
        "indicators": [], "reasoning": "UNION SELECT in a parameter.",
        "limitations": [], "recommended_actions": ["Review the incident."],
        "deterministic_findings": [], "parse_ok": True, "truncated": False,
        "output_tokens": 42, "latency_ms": 5, "raw_output": "{}", "error": None,
    })
    s = SessionLocal()
    ev = log_event(s, event_type="http.200", category="web_attack", severity="high",
                   source="middleware", route="/search", method="GET", http_status=200,
                   evidence="id=1 UNION SELECT password FROM users--")
    job = auto.process_one(s)
    guard = 0
    while job is not None and guard < 50:
        done = s.query(AutomationJob).filter(AutomationJob.event_id == ev.id).first()
        if done is not None and done.status == "completed":
            break
        job = auto.process_one(s)
        guard += 1
    done = s.query(AutomationJob).filter(AutomationJob.event_id == ev.id).first()
    assert done.status == "completed"
    # Fusion arithmetic, unchanged by intelligence: deterministic rules
    # score 0 on this text, confident model threat counts 50%, so the
    # fused verdict is needs_review (threshold 65 for likely_threat).
    assert done.verdict == "needs_review"
    assert done.attack_category == "web_attack"
    assert done.attack_type == "sql_injection"
    assert done.mitre_technique is None  # SQLi proposes no technique
    assessment = json.loads(done.assessment_json)
    assert assessment["intelligence"]["attack_type"] == "sql_injection"
    assert done.incident_id is not None
    inc = s.query(SentinelIncident).filter(SentinelIncident.id == done.incident_id).first()
    assert inc.attack_type == "sql_injection"
    assert inc.attack_category == "web_attack"
    assert inc.analysis_timestamp is not None
    assert inc.review_status == "candidate"  # a training candidate was created
    s.close()


def test_sentinel_analyze_returns_and_stores_intelligence(admin_client, admin, monkeypatch):
    import app.services.classifier as clf
    from app.database import SessionLocal
    from app.models.sentinel_incident import SentinelIncident

    monkeypatch.setattr(clf, "classify_log", lambda *a, **kw: {
        "source": "cyberllm", "status": "ok",
        "classification": "likely_threat", "model_classification": "likely_threat",
        "confidence": "high", "summary": "SQL injection attempt.",
        "indicators": [], "reasoning": "UNION SELECT in a parameter.",
        "limitations": [], "recommended_actions": ["Review the incident."],
        "deterministic_findings": [], "parse_ok": True, "truncated": False,
        "output_tokens": 42, "latency_ms": 5, "raw_output": "{}", "error": None,
    })
    res = admin_client._client.post("/api/sentinel/analyze", json={
        "log_text": "id=1 UNION SELECT password FROM users--",
        "create_incident": True,
    }, headers={"X-CSRF-Token": admin_client._csrf()})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["intelligence"]["attack_type"] == "sql_injection"
    assert body["intelligence"]["attack_category"] == "web_attack"
    assert body["intelligence"]["mitre_technique_id"] is None
    assert body["incident_id"] is not None
    s = SessionLocal()
    inc = s.query(SentinelIncident).filter(
        SentinelIncident.id == body["incident_id"]).first()
    assert inc.attack_type == "sql_injection"
    assert inc.review_status == "candidate"
    s.close()


def test_migration_adds_intelligence_columns_to_old_schema(tmp_path):
    """Regression for the Stage 5 migration: an old-schema database
    gains the new columns, keeps its rows, and leaves the new columns
    NULL (never backfilled by guessing)."""
    import sqlite3

    from sqlalchemy import create_engine, inspect, text

    from app.database import _run_migrations

    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE sentinel_incidents (id INTEGER PRIMARY KEY, log_text TEXT NOT NULL, status VARCHAR(20) NOT NULL, containment_meta TEXT)")
    con.execute("INSERT INTO sentinel_incidents VALUES (1, 'old incident', 'pending_review', NULL)")
    con.execute("CREATE TABLE automation_jobs (id INTEGER PRIMARY KEY, event_id INTEGER UNIQUE, status VARCHAR(20) NOT NULL, verdict VARCHAR(20), mitre_technique VARCHAR(40))")
    con.execute("INSERT INTO automation_jobs VALUES (1, 99, 'completed', 'likely_threat', NULL)")
    con.commit()
    con.close()
    engine = create_engine(f"sqlite:///{path}")
    _run_migrations(engine)
    insp = inspect(engine)
    inc_cols = {c["name"] for c in insp.get_columns("sentinel_incidents")}
    assert {
        "attack_category", "attack_type", "attack_subtype",
        "classification_confidence", "classification_evidence",
        "attack_outcome", "mitre_tactic", "mitre_technique_id",
        "mitre_technique_name", "mitre_subtechnique_id",
        "mitre_subtechnique_name", "mitre_mapping_confidence",
        "mitre_mapping_rationale", "mitre_dataset_version",
        "model_version", "adapter_version", "analysis_timestamp",
        "review_status",
    } <= inc_cols
    job_cols = {c["name"] for c in insp.get_columns("automation_jobs")}
    assert {"attack_category", "attack_type"} <= job_cols
    with engine.connect() as conn:
        assert conn.execute(text(
            "SELECT log_text FROM sentinel_incidents WHERE id=1")).scalar() == "old incident"
        assert conn.execute(text(
            "SELECT attack_category FROM sentinel_incidents WHERE id=1")).scalar() is None
    engine.dispose()


def test_create_incident_persists_intelligence(db):
    intel = build_intelligence("id=1 UNION SELECT password FROM users--", mitre=False)
    inc = create_incident(
        db, log_text="id=1 UNION SELECT password FROM users--",
        ip_address="203.0.113.7",
        fused={"fused_score": 80, "fused_verdict": "likely_threat", "rules": {"evidence": []}},
        classification={"summary": "s", "status": "ok"},
        intelligence=intel, model_version="Qwen/Qwen3-1.7B", adapter_version="abc123")
    assert inc.attack_type == "sql_injection"
    assert inc.attack_category == "web_attack"
    assert inc.model_version == "Qwen/Qwen3-1.7B"
    assert inc.review_status == "unreviewed"
    fresh = db.query(SentinelIncident).filter(SentinelIncident.id == inc.id).first()
    assert fresh.attack_type == "sql_injection"
    restored = incident_intelligence_dict(fresh)
    assert restored["attack_type"] == "sql_injection"
    assert restored["findings"]
    assert incident_intelligence_dict(_blank_incident()) is None
