"""Diagnostics: scanner-safety must pass when refusals work, and the
report check must not litter the user data directory."""

from ..config import Settings
from ..diagnostics import check_scanner_safety, run_diagnostics


def test_scanner_safety_passes_when_refusals_hold():
    result = check_scanner_safety()
    assert result.status == "pass"
    assert "refusals hold" in result.detail


def test_check_reports_includes_autosave(tmp_path):
    """The self-test must exercise the auto-save path the Scanner
    page now relies on, not just the manual exporters."""
    import json

    from ..diagnostics import check_reports

    result = check_reports(tmp_path)
    assert result.status == "pass"
    autosaved = sorted(tmp_path.glob("selftest-*.json"))
    assert len(autosaved) == 1
    data = json.loads(autosaved[0].read_text(encoding="utf-8"))
    assert [f["name"] for f in data["findings"]] == ["Self-test finding"]
    assert sorted(tmp_path.glob("selftest-*.html"))


def test_run_diagnostics_rows_and_no_litter(tmp_path):
    results = run_diagnostics(Settings(), tmp_path)
    names = [r.name for r in results]
    for expected in ("Project root", "Backend Python", "Model artifacts",
                     "GPU", "Data directory writable", "Backend API",
                     "Model inference", "Scanner safety",
                     "Report generation"):
        assert expected in names
    safety = [r for r in results if r.name == "Scanner safety"][0]
    assert safety.status == "pass"
    assert not list(tmp_path.glob("selftest.*"))
