"""Detection-to-report contract: scan findings must survive into a
durable report, and a failed scan must never leave a stale result
exportable as if it were current.

These tests go through the real page methods (ScannerPage._scan_done /
_scan_error, DemoPage scripted-scan completion, ReportsPage.refresh)
with real ScanResult/Finding objects. No backend is involved: scan
reports are deterministic by design, so saving them must work even
when the model/backend is unavailable.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import json

import pytest
from PySide6.QtWidgets import QApplication

from ..cases import CaseStore
from ..config import Settings
from ..gui.context import AppContext
from ..gui.page_misc import DemoPage, ReportsPage
from ..gui.page_scanner import ScannerPage
from ..scanner.engine import ScanResult
from ..scanner.findings import Finding
from ..timeline import Timeline


class FakeBackend:
    def __init__(self, settings):
        self.settings = settings
        self.started_by_gui = False
        self.log_lines = []

    @property
    def running(self):
        return False

    def stop(self):
        return True, "stopped"


class FakeClient:
    api_base = "http://127.0.0.1:8000"


class FakeAdminClient:
    pass


@pytest.fixture(scope="module")
def qapp():
    app = QApplication.instance()
    return app or QApplication([])


@pytest.fixture
def ctx(tmp_path):
    settings = Settings()
    return AppContext(
        settings=settings, data_dir=tmp_path,
        backend=FakeBackend(settings), client=FakeClient(),
        admin_client=FakeAdminClient(),
        cases=CaseStore(tmp_path / "cases.json"),
        timeline=Timeline(tmp_path / "timeline.jsonl"),
        dirs={"reports": tmp_path / "reports", "logs": tmp_path / "logs",
              "history": tmp_path / "history"})


def _finding(name, severity="High", status="suspected"):
    return Finding(name, "Sensitive files", severity, "medium", status,
                   f"Explanation for {name}", f"Evidence for {name}",
                   "http://127.0.0.1:9/.env", "impact", "remediation")


def _result(findings, target="http://127.0.0.1:9/",
            started="2026-10-29T22:00:00", errors=None):
    from ..scanner.findings import summarize

    return ScanResult(
        target=target, started_at=started, finished_at="2026-10-29T22:00:05",
        findings=list(findings), summary=summarize(findings),
        requests_made=31, stopped=False, errors=list(errors or []),
        timeline=[], limitations=[])


def _saved_jsons(ctx):
    reports = ctx.dirs["reports"]
    if not reports.exists():
        return []
    return sorted(reports.glob("*.json"))


def test_completed_scan_is_saved_to_reports_dir(qapp, ctx):
    """A finished scan must leave a durable report with its findings."""
    page = ScannerPage(ctx)
    worker = object()
    page._worker = worker
    result = _result([_finding("Exposed .env file", "High"),
                      _finding("Missing security header", "Low",
                               "verified")])
    page._scan_done(result, worker)

    saved = _saved_jsons(ctx)
    assert len(saved) == 1
    data = json.loads(saved[0].read_text(encoding="utf-8"))
    assert data["target"] == "http://127.0.0.1:9/"
    names = [f["name"] for f in data["findings"]]
    assert "Exposed .env file" in names
    assert "Missing security header" in names
    env = [f for f in data["findings"]
           if f["name"] == "Exposed .env file"][0]
    assert env["evidence"] == "Evidence for Exposed .env file"
    assert env["severity"] == "High"
    assert env["status"] == "suspected"
    html_files = sorted(ctx.dirs["reports"].glob("*.html"))
    assert len(html_files) == 1
    html = html_files[0].read_text(encoding="utf-8")
    assert "Exposed .env file" in html
    assert "Missing security header" in html


def test_failed_scan_clears_stale_result(qapp, ctx):
    """After a scan fails, the previous scan must not stay exportable."""
    page = ScannerPage(ctx)
    old = _result([_finding("Old finding")])
    page._result = old
    page.table.setRowCount(1)
    worker = object()
    page._worker = worker
    page._scan_error("host not on the allowlist", worker)
    assert page._result is None
    assert page.table.rowCount() == 0
    assert "not on the allowlist" in page.status_label.text()


def test_demo_scripted_scan_result_is_saved(qapp, ctx):
    """A demo scripted scan must not discard its findings silently."""
    page = DemoPage(ctx)
    result = _result([_finding("Demo finding", "Medium")])
    page._scripted_done(result)
    saved = _saved_jsons(ctx)
    assert len(saved) == 1
    data = json.loads(saved[0].read_text(encoding="utf-8"))
    assert [f["name"] for f in data["findings"]] == ["Demo finding"]
    assert "Scanner page for detail" not in page.status_label.text()
    assert "SIMULATED" in page.status_label.text()


def test_two_scans_do_not_overwrite_each_other(qapp, ctx):
    """Two scans with the same target and timestamp keep both reports."""
    page = ScannerPage(ctx)
    worker = object()
    page._worker = worker
    page._scan_done(_result([_finding("First scan finding")]), worker)
    page._worker = worker
    page._scan_done(_result([_finding("Second scan finding")]), worker)
    saved = _saved_jsons(ctx)
    assert len(saved) == 2
    all_names = []
    for path in saved:
        all_names += [f["name"]
                      for f in json.loads(path.read_text(encoding="utf-8"))["findings"]]
    assert "First scan finding" in all_names
    assert "Second scan finding" in all_names


def test_saved_report_appears_in_reports_page_after_refresh(qapp, ctx):
    """Reports & History must list the saved report after refresh."""
    scanner = ScannerPage(ctx)
    worker = object()
    scanner._worker = worker
    scanner._scan_done(_result([_finding("Refreshable finding")]), worker)
    reports = ReportsPage(ctx)
    reports.refresh()
    listed = [reports.list_widget.item(i).text()
              for i in range(reports.list_widget.count())]
    # One auto-saved scan leaves a JSON record and its HTML report.
    json_files = [p for p in listed if p.endswith(".json")]
    html_files = [p for p in listed if p.endswith(".html")]
    assert len(json_files) == 1
    assert len(html_files) == 1
    data = json.loads(open(json_files[0], encoding="utf-8").read())
    assert data["target"] == "http://127.0.0.1:9/"
    assert data["findings"][0]["name"] == "Refreshable finding"


def test_empty_scan_with_errors_is_saved_honestly(qapp, ctx):
    """A failed/empty scan saves its errors, never a clean bill."""
    page = ScannerPage(ctx)
    worker = object()
    page._worker = worker
    page._scan_done(
        _result([], errors=["check refused: host not on the allowlist"]),
        worker)
    saved = _saved_jsons(ctx)
    assert len(saved) == 1
    data = json.loads(saved[0].read_text(encoding="utf-8"))
    assert data["findings"] == []
    assert data["errors"] == ["check refused: host not on the allowlist"]


def test_table_filters_do_not_change_saved_report(qapp, ctx):
    """Hiding a finding in the table must not remove it from the report."""
    page = ScannerPage(ctx)
    worker = object()
    page._worker = worker
    page._scan_done(_result([_finding("High finding", "High"),
                             _finding("Low finding", "Low")]), worker)
    page.cb_sev.setCurrentText("Low")
    assert page.table.rowCount() == 1  # only the Low row is shown
    saved = _saved_jsons(ctx)
    assert len(saved) == 1
    data = json.loads(saved[0].read_text(encoding="utf-8"))
    names = [f["name"] for f in data["findings"]]
    assert "High finding" in names
    assert "Low finding" in names
