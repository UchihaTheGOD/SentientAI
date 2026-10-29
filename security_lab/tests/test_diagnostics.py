"""Diagnostics: scanner-safety must pass when refusals work, and the
report check must not litter the user data directory."""

from ..config import Settings
from ..diagnostics import check_scanner_safety, run_diagnostics


def test_scanner_safety_passes_when_refusals_hold():
    result = check_scanner_safety()
    assert result.status == "pass"
    assert "refusals hold" in result.detail


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
