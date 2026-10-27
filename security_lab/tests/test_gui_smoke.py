"""Offscreen GUI smoke tests (no window shown, no network).

Pages are built with stub backend/client objects so construction and
pure-UI behaviour can be verified without a live backend.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

from ..cases import CaseStore
from ..config import Settings
from ..gui.context import AppContext
from ..gui.main import MainWindow, PAGES
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
