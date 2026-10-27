"""Scanner checks against the local lab: expected findings, and the
hard guarantee that sensitive-file bodies are never stored."""

from ..lab_server import start_lab_server, stop_lab_server
from ..scanner.engine import ScanConfig, Scanner

SECRET_MARKER = "FAKE-NOT-A-REAL-SECRET"


def _scan(target, **overrides):
    cfg = ScanConfig(target=target, allowlist=["127.0.0.1"],
                     local_lab_enabled=True, authorized=True,
                     rate_limit_seconds=0.01, timeout_seconds=5,
                     **overrides)
    return Scanner(cfg).run()


def test_lab_index_scan_expected_findings():
    server, _thread, url = start_lab_server()
    try:
        result = _scan(url)
    finally:
        stop_lab_server(server)
    assert not result.errors
    names = [f.name for f in result.findings]
    assert any("Sensitive file publicly accessible: /.env" in n for n in names)
    assert any("Public file present: /robots.txt" in n for n in names)
    assert any("Directory listing enabled: /uploads/" in n for n in names)
    assert any("API documentation publicly accessible" in n for n in names)
    assert any("Admin path reachable" in n for n in names)
    assert any("Content Security Policy" in n for n in names)
    # The .env finding must be "suspected", never "verified": the body
    # was not inspected, only the status code.
    env = [f for f in result.findings if "/.env" in f.name][0]
    assert env.status == "suspected"
    assert env.severity == "High"


def test_sensitive_file_body_never_stored():
    server, _thread, url = start_lab_server()
    try:
        result = _scan(url)
        search = _scan(url + "/search?q=hello")
    finally:
        stop_lab_server(server)
    for finding in result.findings + search.findings:
        assert SECRET_MARKER not in finding.evidence
        assert SECRET_MARKER not in finding.explanation
        assert SECRET_MARKER not in finding.name
    assert SECRET_MARKER not in str(result.to_dict())
    assert SECRET_MARKER not in str(search.to_dict())


def test_reflection_detected_on_search_target():
    server, _thread, url = start_lab_server()
    try:
        result = _scan(url + "/search?q=hello")
    finally:
        stop_lab_server(server)
    names = [f.name for f in result.findings]
    assert any("Reflected input in parameter: q" in n for n in names)
    reflected = [f for f in result.findings if "Reflected input" in f.name][0]
    assert reflected.status == "suspected"
    # Reflection alone is Low confidence, never a confirmed XSS.
    assert reflected.severity == "Low"


def test_category_selection_limits_checks():
    server, _thread, url = start_lab_server()
    try:
        result = _scan(url, categories={"cookies"})
    finally:
        stop_lab_server(server)
    assert all(f.category == "Cookies and session security"
               for f in result.findings)
