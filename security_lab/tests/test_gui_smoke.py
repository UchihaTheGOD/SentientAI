"""Offscreen GUI smoke tests (no window shown, no network).

Pages are built with stub backend/client objects so construction and
pure-UI behaviour can be verified without a live backend.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication, QFileDialog

from ..cases import CaseStore
from ..client import AuthError
from ..config import Settings
from ..evaluation import EvalResult
from ..gui.context import AppContext
from ..gui.main import MainWindow, PAGES
from ..gui.page_control import ControlCenterPage
from ..gui.page_misc import DemoPage, SettingsPage
from ..gui.page_model import ModelTestingPage
from ..gui.page_scanner import ScannerPage
from ..gui.page_users import UserManagementPage
from ..model import EXAMPLE_CASES
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


class FakeAdminClient:
    def __init__(self):
        self.listed = None

    def list_users(self, **kwargs):
        self.listed = kwargs
        users = [
            {"id": 1, "username": "alice", "email": "alice@example.test",
             "role": "user", "is_active": True, "is_suspended": False,
             "suspension_reason": None, "display_name": None,
             "created_at": "2026-10-28T00:00:00", "can_sign_in": True},
            {"id": 2, "username": "boss", "email": "boss@example.test",
             "role": "admin", "is_active": True, "is_suspended": False,
             "suspension_reason": None, "display_name": None,
             "created_at": "2026-10-27T00:00:00", "can_sign_in": True},
        ]
        return {"total": 2, "admins": 1, "active": 2, "suspended": 0,
                "users": users, "recent": users, "page": 1, "per_page": 25}


class FakeClient:
    api_base = "http://127.0.0.1:8000"


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


def test_main_window_builds_all_pages(qapp, ctx):
    window = MainWindow(ctx)
    assert window.stack.count() == len(PAGES) == 9
    window.switch_page("users")
    assert window.nav.currentRow() == 3
    window.switch_page("scanner")
    assert window.nav.currentRow() == 1
    window.close()


def test_users_page_renders_stub_data(qapp, ctx):
    page = UserManagementPage(ctx)
    page.refresh()
    assert page.table.rowCount() == 2
    assert page.lbl_total.text() == "Total: 2"
    assert page.lbl_admins.text() == "Admins: 1"
    assert "password_hash" not in page.detail.toPlainText()
    page.table.selectRow(0)
    assert "alice" in page.detail.toPlainText()


def test_control_logs_placeholder_when_empty(qapp, ctx):
    """An empty log view must explain itself instead of looking broken."""
    page = ControlCenterPage(ctx)
    page.refresh_logs()
    assert "tailed only" in page.log_view.toPlainText()


def test_scanner_page_validation_blocks_unsafe_starts(qapp, ctx):
    page = ScannerPage(ctx)
    page.start_scan()
    assert "target URL" in page.status_label.text()
    page.ed_target.setText("http://127.0.0.1:9/")
    page.start_scan()
    assert "authorization" in page.status_label.text()
    assert page._worker is None


def test_model_page_example_loads(qapp, ctx):
    page = ModelTestingPage(ctx)
    page.cb_example.setCurrentIndex(1)
    assert page.ed_input.toPlainText() == EXAMPLE_CASES[0]["text"]
    assert page.cb_kind.currentText() == EXAMPLE_CASES[0]["kind"]


# ------------------------------------------------------- hardening additions

def test_scanner_progress_slot_and_stale_worker_guard(qapp, ctx):
    from types import SimpleNamespace

    page = ScannerPage(ctx)
    page._on_scan_progress(50, 100, "Running: x")
    assert page.progress.value() == 50
    result = SimpleNamespace(target="http://127.0.0.1:9/", findings=[],
                             summary={}, requests_made=0,
                             stopped=False, errors=[])
    current, other = object(), object()
    page._worker = current
    page._scan_done(result, other)
    assert page._result is None  # stale worker ignored
    page._scan_done(result, current)
    assert page._result is result
    assert page._worker is None
    assert page.btn_scan.isEnabled()
    page._worker = current
    page.btn_scan.setEnabled(False)
    page._scan_error("boom", other)
    assert not page.btn_scan.isEnabled()  # stale error ignored
    page._scan_error("boom", current)
    assert page.btn_scan.isEnabled()
    assert "boom" in page.status_label.text()
    assert page._worker is None


def test_scanner_start_lab_failure_is_reported(qapp, ctx, monkeypatch):
    import security_lab.gui.page_scanner as mod

    def boom():
        raise OSError("bind failed")

    monkeypatch.setattr(mod, "start_lab_server", boom)
    page = ScannerPage(ctx)
    page.start_lab()
    assert "failed" in page.lbl_lab.text()
    assert page.btn_lab.isEnabled()


def test_control_backend_error_reenables_buttons(qapp, ctx):
    page = ControlCenterPage(ctx)
    page._set_busy(True)
    assert not page.btn_start.isEnabled()
    page._backend_error("boom")
    assert page.btn_start.isEnabled()
    assert "boom" in page.status_label.text()


def test_control_port_range_is_validated(qapp, ctx):
    page = ControlCenterPage(ctx)
    page.ed_port.setText("99999")
    page.save_settings()
    assert "65535" in page.lbl_cfg_status.text()
    assert ctx.settings.api_port == 8000  # unchanged


def test_control_refresh_fields_picks_up_settings(qapp, ctx):
    page = ControlCenterPage(ctx)
    ctx.settings.api_host = "10.9.9.9"
    page._refresh_fields()
    assert page.ed_host.text() == "10.9.9.9"


def test_model_export_uses_save_dialog(qapp, ctx, monkeypatch, tmp_path):
    target = tmp_path / "evaluation.json"
    monkeypatch.setattr(
        QFileDialog, "getSaveFileName",
        staticmethod(lambda *args, **kwargs: (str(target), "")))

    def _must_not_open(*args, **kwargs):
        raise AssertionError("export must use a save dialog")

    monkeypatch.setattr(QFileDialog, "getOpenFileName",
                        staticmethod(_must_not_open))
    page = ModelTestingPage(ctx)
    page._eval_result = EvalResult(cases=[], metrics=None)
    page._export_eval("json")
    assert target.exists()
    assert "exported" in page.lbl_batch_file.text()


def test_model_save_baseline_failure_is_reported(qapp, ctx, monkeypatch):
    import security_lab.gui.page_model as mod

    def boom(result, path):
        raise OSError("disk full")

    monkeypatch.setattr(mod, "save_baseline", boom)
    page = ModelTestingPage(ctx)
    page._eval_result = EvalResult(cases=[], metrics=None)
    page._save_baseline()
    assert "failed" in page.lbl_batch_file.text()


def test_model_batch_done_reenables_button(qapp, ctx):
    page = ModelTestingPage(ctx)
    page.btn_batch.setEnabled(False)
    result = EvalResult(
        cases=[],
        metrics={"total": 0, "decided": 0, "abstained": 0, "errors": 0,
                 "accuracy": None, "threat_recall": None,
                 "false_positive_rate": None, "per_class": {},
                 "per_kind": {}, "confusion_matrix": {}})
    page._batch_done(result)
    assert page.btn_batch.isEnabled()
    assert page.progress.value() == 100


def test_model_signin_own_exception_is_reported(qapp, ctx, monkeypatch):
    import security_lab.gui.dialogs as dialogs

    answers = iter(["admin", "secret"])
    monkeypatch.setattr(dialogs, "ask_text",
                        lambda *args, **kwargs: next(answers))

    class BoomClient:
        def login(self, username, password):
            raise RuntimeError("boom")

    ctx.client = BoomClient()
    page = ModelTestingPage(ctx)
    page._signin_own()  # must not raise
    assert "boom" in page.lbl_auth.text()


def test_users_search_is_debounced(qapp, ctx):
    page = UserManagementPage(ctx)
    assert ctx.admin_client.listed is None
    page.ed_search.setText("ali")
    assert ctx.admin_client.listed is None  # no request yet
    page._search_timer.timeout.emit()
    assert ctx.admin_client.listed is not None


def test_users_auth_error_disables_actions(qapp, ctx):
    page = UserManagementPage(ctx)
    page._set_actions_enabled(True)

    def _raise():
        raise AuthError("expired")

    page._call(_raise, "ok")
    assert not page.btn_create.isEnabled()
    assert "Session expired" in page.status_label.text()


def test_settings_save_rejects_bad_bounds(qapp, ctx):
    page = SettingsPage(ctx)
    page.ed_timeout.setText("0")
    page._save()
    assert "timeout" in page.status_label.text().lower()
    assert ctx.settings.request_timeout_seconds == 10.0


def test_settings_reset_refreshes_fields(qapp, ctx, monkeypatch):
    import security_lab.gui.page_misc as mod

    monkeypatch.setattr(mod, "confirm", lambda *args, **kwargs: True)
    page = SettingsPage(ctx)
    page.ed_api_host.setText("10.9.9.9")
    page._reset()
    assert page.ed_api_host.text() == "127.0.0.1"
    assert page.status_label.text() == "Settings reset to defaults."


def test_demo_simulation_results_use_stub_client(qapp, ctx):
    class StubClient:
        def screen(self, log):
            return {"findings": [{"rule": "ssrf-rule"}]}

        def analyze(self, log, kind):
            return {"classification": "likely_threat",
                    "decision_source": "model"}

    ctx.client = StubClient()
    page = DemoPage(ctx)
    res = page._simulation_results()
    assert "ssrf-rule" in res["rule"]
    assert "likely_threat" in res["model"]

    class FailClient:
        def screen(self, log):
            raise RuntimeError("down")

        def analyze(self, log, kind):
            raise RuntimeError("down")

    ctx.client = FailClient()
    res = page._simulation_results()
    assert "not measured" in res["rule"]
    assert "not measured" in res["model"]


def test_demo_start_lab_failure_is_reported(qapp, ctx, monkeypatch):
    import security_lab.gui.page_misc as mod

    def boom():
        raise OSError("bind failed")

    monkeypatch.setattr(mod, "start_lab_server", boom)
    page = DemoPage(ctx)
    page._start_lab()
    assert "failed" in page.lbl_lab.text()
