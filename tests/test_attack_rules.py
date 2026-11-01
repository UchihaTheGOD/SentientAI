"""Stage 4 attack-rule tests: deterministic categories, auth-pattern
distinctions, and the MITRE no-auto-mapping guard."""
import pytest

from app.services.attack_rules import (
    COMPILED_RULES,
    analyze_text,
    classify_auth_attempts,
    suggest_mitre,
)
from app.services.mitre_attack import MitreAttack


def mitre_or_skip():
    try:
        return MitreAttack.load_default()
    except Exception:
        pytest.skip("MITRE dataset not imported (run scripts/import_mitre.py)")


def _types(findings):
    return {f["attack_type"] for f in findings}


def test_no_rule_matches_empty_string():
    for _, _, _, _, patterns in COMPILED_RULES:
        for p in patterns:
            assert not p.search(""), f"vacuous pattern: {p.pattern}"


def test_web_attack_patterns():
    assert "sql_injection" in _types(analyze_text("id=1 UNION SELECT password FROM users--"))
    assert "cross_site_scripting" in _types(analyze_text("<script>alert(document.cookie)</script>"))
    assert "path_traversal" in _types(analyze_text("GET /files/../../etc/passwd"))
    assert "command_injection" in _types(analyze_text("q=test; id"))
    assert "server_side_template_injection" in _types(analyze_text("name={{7*7}}"))
    assert "xml_external_entity" in _types(analyze_text('<?xml <!ENTITY xxe SYSTEM "file:///etc/passwd">'))
    assert "local_file_inclusion" in _types(analyze_text("page=php://filter/convert.base64-encode/resource=index"))
    assert "web_shell_indicator" in _types(analyze_text("GET /uploads/c99.php?cmd=id"))


def test_ssrf_text_and_metadata():
    assert "server_side_request_forgery" in _types(
        analyze_text("GET /proxy?url=http://169.254.169.254/latest/meta-data/"))
    findings = analyze_text("GET /fetch", metadata={"url": "http://metadata.google.internal/"})
    assert "server_side_request_forgery" in _types(findings)
    assert findings[0]["confidence"] == "high"


def test_benign_and_ambiguous_produce_no_attack_findings():
    assert analyze_text("User john failed to log in") == []
    assert analyze_text("GET /blog/hello-world 200") == []
    assert analyze_text("Select a category to continue") == []
    assert analyze_text("") == []
    assert analyze_text("   ") == []


def test_auth_bypass_context_from_credential_field():
    findings = analyze_text("username=' OR '1'='1", metadata={"param": "username"})
    assert "auth_bypass" in _types(findings)
    sql = [f for f in findings if f["attack_type"] == "sql_injection"]
    assert sql and sql[0]["attack_subtype"] == "auth_bypass_via_injection"


def test_outcome_never_confirmed_from_rules():
    findings = analyze_text("id=1 UNION SELECT password FROM users--")
    assert findings
    assert all(f["outcome"] == "attempted_or_detected" for f in findings)
    assert all(f["mitre_suggestion"] is None for f in findings)


def test_auth_classifier_guessing_spraying_stuffing_brute_force():
    one_user = [{"username": "alice", "success": False}] * 8
    assert classify_auth_attempts(one_user)["attack_type"] == "password_guessing"

    spraying = [{"username": f"user{i}", "success": False, "password_hash": "h1"}
                for i in range(6)]
    assert classify_auth_attempts(spraying)["attack_type"] == "password_spraying"

    stuffing = []
    for i in range(12):
        stuffing.append({"username": f"victim{i}", "success": False,
                         "password_hash": f"hash{i}"})
    assert classify_auth_attempts(stuffing)["attack_type"] == "credential_stuffing"

    brute = [{"username": "alice", "success": False}] * 60
    assert classify_auth_attempts(brute)["attack_type"] == "brute_force"

    assert classify_auth_attempts([{"username": "a", "success": False}] * 3) is None


def test_auth_classifier_ambiguous_without_hashes_is_low_confidence_spraying():
    attempts = [{"username": f"user{i}", "success": False} for i in range(6)]
    result = classify_auth_attempts(attempts)
    assert result["attack_type"] == "password_spraying"
    assert result["confidence"] == "low"
    assert "cannot be distinguished" in result["evidence"][0]


def test_mitre_suggestions_only_for_allowed_types():
    m = mitre_or_skip()
    guessing = classify_auth_attempts([{"username": "a", "success": False}] * 8)
    s = suggest_mitre(guessing, m)
    assert s["technique_id"] == "T1110.001" and s["technique_name"] == "Password Guessing"
    assert s["tactics"][0]["tactic_id"] == "TA0006"
    assert s["rationale"] and s["url"]

    spraying = classify_auth_attempts(
        [{"username": f"u{i}", "success": False, "password_hash": "h"} for i in range(6)])
    assert suggest_mitre(spraying, m)["technique_id"] == "T1110.003"

    stuffing = classify_auth_attempts(
        [{"username": f"v{i}", "success": False, "password_hash": f"h{i}"} for i in range(12)])
    assert suggest_mitre(stuffing, m)["technique_id"] == "T1110.004"

    brute = classify_auth_attempts([{"username": "a", "success": False}] * 60)
    assert suggest_mitre(brute, m)["technique_id"] == "T1110"


def test_no_auto_t1190_for_web_attacks():
    m = mitre_or_skip()
    for text in ("id=1 UNION SELECT password FROM users--",
                 "<script>alert(1)</script>",
                 "GET /files/../../etc/passwd",
                 "GET /proxy?url=http://169.254.169.254/"):
        for finding in analyze_text(text):
            assert suggest_mitre(finding, m) is None, finding["attack_type"]


def test_web_shell_suggests_validated_t1505_003():
    m = mitre_or_skip()
    findings = analyze_text("GET /uploads/c99.php?cmd=id")
    shell = next(f for f in findings if f["attack_type"] == "web_shell_indicator")
    s = suggest_mitre(shell, m)
    assert s["technique_id"] == "T1505.003"
    assert s["technique_name"] == "Web Shell"
    assert s["tactics"][0]["tactic_id"] == "TA0003"


def test_suggest_mitre_fails_closed_without_dataset():
    finding = classify_auth_attempts([{"username": "a", "success": False}] * 8)
    assert suggest_mitre(finding, MitreAttack([])) is None


def test_dns_tunneling_heuristic_on_structured_hostname():
    host = "a" * 45 + ".example.com"
    findings = analyze_text("DNS query", metadata={"hostname": host})
    assert "dns_tunneling_indicator" in _types(findings)
    assert findings[0]["confidence"] == "low"


def test_benign_lookalikes_produce_no_findings():
    # Words that LOOK attack-adjacent but carry no injection syntax,
    # no traversal sequence, no shell metacharacter context.
    lookalikes = [
        "GET /search?q=select+statement",
        "Union membership page",
        "JavaScript framework documentation",
        "How to write a shell script tutorial",
        "Learn about metadata standards",
        "command line tools reference",
        "SELECTED: quarterly report",
        "password reset instructions sent to your email",
        "GET /api/users/42 200",
        "path traversal in hiking guides",
    ]
    for text in lookalikes:
        assert analyze_text(text) == [], text


def test_ambiguous_prose_and_missing_metadata():
    # Prose about attacks is not an attack signal; rules need structure.
    assert analyze_text("multiple failed logins detected overnight") == []
    assert analyze_text("suspicious activity observed") == []
    assert analyze_text("error 500 on /login") == []
    # DoS has no single-event rule by design (aggregation only).
    assert analyze_text("100 requests per second") == []
    # Missing/empty metadata must never break analysis.
    ssrf = "GET /proxy?url=http://169.254.169.254/latest/meta-data/"
    assert "server_side_request_forgery" in _types(analyze_text(ssrf, metadata=None))
    assert "server_side_request_forgery" in _types(analyze_text(ssrf, metadata={}))
    assert "server_side_request_forgery" in _types(
        analyze_text(ssrf, metadata={"url": None}))
    assert analyze_text("ordinary request", metadata={"param": "username"}) == []
