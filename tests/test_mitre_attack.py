"""Stage 4 MITRE tests: local STIX v20.0 lookups and validation.

Tests that need the real bundle skip cleanly when it has not been
imported (scripts/import_mitre.py) — the bundle is gitignored by
design, so a fresh checkout without an import must not fail the suite.
"""
import hashlib
from pathlib import Path

import pytest

from app.services.mitre_attack import DATA_DIR, MitreAttack, get_mitre, normalize_id

BUNDLE = DATA_DIR / "enterprise-attack-20.0.json"


def mitre_or_skip():
    try:
        return MitreAttack.load_default()
    except Exception:
        pytest.skip("MITRE dataset not imported (run scripts/import_mitre.py)")


def test_normalize_id():
    assert normalize_id("t1110.001") == "T1110.001"
    assert normalize_id(" T1190 ") == "T1190"
    assert normalize_id("t1110.1") is None  # short sub-ids are malformed, never padded
    assert normalize_id("T999") is None
    assert normalize_id("T1110.12") is None
    assert normalize_id("not-a-technique") is None
    assert normalize_id("") is None


def test_dataset_version_and_counts():
    m = mitre_or_skip()
    info = m.dataset_info()
    assert info["version"] == "20.0"
    assert info["object_count"] == 26690
    assert info["techniques"] == 227
    assert info["subtechniques"] == 479
    assert info["tactics"] == 15
    assert info["analytics"] == 1770
    assert info["bundle_modified"] == "2026-10-13T17:53:10.145Z"
    # Manifest hash matches the file on disk (no silent swap).
    assert info["bundle_sha256"] == hashlib.sha256(BUNDLE.read_bytes()).hexdigest()
    assert info["bundle_bytes"] == BUNDLE.stat().st_size


def test_resolve_spraying_with_parent_tactic_url():
    m = mitre_or_skip()
    r = m.resolve("T1110.003")
    assert r["technique_name"] == "Password Spraying"
    assert r["is_subtechnique"] is True
    assert r["parent"] == {"technique_id": "T1110", "technique_name": "Brute Force"}
    assert r["tactics"] == [{"tactic_id": "TA0006", "tactic_name": "Credential Access",
                             "tactic_shortname": "credential-access"}]
    assert r["url"] == "https://attack.mitre.org/techniques/T1110/003"


def test_resolve_technique_not_subtechnique():
    m = mitre_or_skip()
    r = m.resolve("T1190")
    assert r["technique_name"] == "Exploit Public-Facing Application"
    assert r["is_subtechnique"] is False
    assert r["parent"] is None
    assert r["tactics"][0]["tactic_shortname"] == "initial-access"


def test_validate_revoked_reports_replacement_without_substituting():
    m = mitre_or_skip()
    v = m.validate("T1066")
    assert v == {"valid": False, "technique_id": "T1066",
                 "reason": "revoked", "replacement": "T1027.005"}
    assert m.resolve("T1066") is None


def test_validate_deprecated_malformed_not_found():
    m = mitre_or_skip()
    assert m.validate("T1153")["reason"] == "deprecated"
    assert m.resolve("T1153") is None
    assert m.validate("T999")["reason"] == "malformed"
    assert m.validate("T9999.999")["reason"] == "not_found"
    assert m.validate("t1110.003")["reason"] == "ok"


def test_validate_subtechnique_mismatch_synthetic():
    fake = {
        "id": "attack-pattern--00000000-0000-4000-8000-000000000001",
        "type": "attack-pattern",
        "name": "Fake",
        "external_references": [{"source_name": "mitre-attack", "external_id": "T9998"}],
        "x_mitre_is_subtechnique": True,
    }
    m = MitreAttack([fake])
    assert m.validate("T9998")["reason"] == "subtechnique_mismatch"
    fake2 = dict(fake, external_references=[
        {"source_name": "mitre-attack", "external_id": "T9998.001"}],
        x_mitre_is_subtechnique=False)
    m2 = MitreAttack([fake2])
    assert m2.validate("T9998.001")["reason"] == "subtechnique_mismatch"


def test_detection_strategies_and_analytics_chain():
    m = mitre_or_skip()
    strategies = m.strategies_for_technique("T1059.001")
    assert any(s["strategy_id"] == "DET0455" for s in strategies)
    analytics = m.analytics_for_strategy("DET0455")
    assert analytics, "expected analytics linked to DET0455 via URL"
    assert all(a["analytic_id"].startswith("AN") for a in analytics)


def test_missing_dataset_fails_closed():
    empty = MitreAttack([])
    assert empty.resolve("T1110.003") is None
    assert empty.validate("T1110.003")["reason"] == "not_found"
    assert empty.dataset_info()["version"] is None


def test_every_suggested_id_validates_with_matching_tactic():
    """The complete suggestion space (5 types): each ID exists, its
    tactic matches the technique's own tactics, sub-technique parents
    are valid techniques, and evidence + rationale survive."""
    from app.services.attack_rules import suggest_mitre

    m = mitre_or_skip()
    cases = [
        ("password_guessing", "T1110.001"),
        ("password_spraying", "T1110.003"),
        ("credential_stuffing", "T1110.004"),
        ("brute_force", "T1110"),
        ("web_shell_indicator", "T1505.003"),
    ]
    for attack_type, expected_id in cases:
        s = suggest_mitre({"attack_type": attack_type, "evidence": ["e1"]}, m)
        assert s is not None, attack_type
        assert s["technique_id"] == expected_id
        assert m.validate(expected_id)["reason"] == "ok"
        resolved = m.resolve(expected_id)
        assert s["tactics"][0]["tactic_id"] in {
            t["tactic_id"] for t in resolved["tactics"]}
        assert s["evidence"] == ["e1"] and s["rationale"]
        assert s["url"].startswith("https://attack.mitre.org/")
        if s["is_subtechnique"]:
            assert s["parent"] is not None
            assert m.validate(s["parent"]["technique_id"])["reason"] == "ok"
        else:
            assert s["parent"] is None


def test_non_candidate_types_never_suggest():
    from app.services.attack_rules import suggest_mitre

    m = mitre_or_skip()
    for attack_type in ("sql_injection", "cross_site_scripting",
                        "path_traversal", "server_side_request_forgery",
                        "command_injection", "dns_tunneling_indicator",
                        "scanning_tool_indicator", "sensitive_file_probe",
                        "repeated_auth_failure"):
        assert suggest_mitre({"attack_type": attack_type, "evidence": []}, m) is None
