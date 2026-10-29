"""Main window: sidebar navigation + stacked tool pages."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import (QApplication, QListWidget, QMainWindow,
                               QSplitter, QStackedWidget, QWidget)

from ..config import Settings, load_settings, user_data_dir
from ..lab_server import stop_lab_server
from .context import AppContext
from .page_control import ControlCenterPage
from .page_misc import (CasesPage, DemoPage, DiagnosticsPage, ReportsPage,
                        SettingsPage)
from .page_model import ModelTestingPage
from .page_scanner import ScannerPage
from .page_users import UserManagementPage
from .theme import DARK_STYLESHEET

PAGES = [
    ("control", "Website & Model Control Center"),
    ("scanner", "Authorized Website Security Scanner"),
    ("model", "Model Testing & Evaluation"),
    ("users", "User Management"),
    ("reports", "Reports & History"),
    ("cases", "Case Management"),
    ("demo", "Classroom Demo"),
    ("diagnostics", "Diagnostics"),
    ("settings", "Settings"),
]


class MainWindow(QMainWindow):
    def __init__(self, ctx: AppContext, parent=None):
        super().__init__(parent)
        self.ctx = ctx
        self.setWindowTitle("CyberLLMv1 Security Lab")
        self.resize(1280, 800)
        self.setStyleSheet(DARK_STYLESHEET)

        self.nav = QListWidget()
        self.stack = QStackedWidget()
        self._pages: dict[str, QWidget] = {}
        page_classes = {
            "control": ControlCenterPage,
            "scanner": ScannerPage,
            "model": ModelTestingPage,
            "users": UserManagementPage,
            "reports": ReportsPage,
            "cases": CasesPage,
            "demo": DemoPage,
            "diagnostics": DiagnosticsPage,
            "settings": SettingsPage,
        }
        ctx.navigate = self.switch_page
        for key, label in PAGES:
            self.nav.addItem(label)
            page = page_classes[key](ctx, self)
            self._pages[key] = page
            self.stack.addWidget(page)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.setCurrentRow(0)

        splitter = QSplitter()
        splitter.addWidget(self.nav)
        splitter.addWidget(self.stack)
        splitter.setSizes([280, 1000])
        self.setCentralWidget(splitter)
        self.statusBar().showMessage(
            "Ready. Start the backend from the Control Center.")

    def switch_page(self, key: str) -> None:
        for idx, (page_key, _label) in enumerate(PAGES):
            if page_key == key:
                self.nav.setCurrentRow(idx)
                return

    def closeEvent(self, event):  # noqa: N802 - Qt naming
        # Stop any running scan first, so a scan thread cannot outlive
        # the window and overwrite state after close.
        scanner = self._pages.get("scanner")
        if scanner is not None and hasattr(scanner, "stop_all"):
            try:
                scanner.stop_all()
            except Exception:
                pass
        demo = self._pages.get("demo")
        if demo is not None and hasattr(demo, "stop_all"):
            try:
                demo.stop_all()
            except Exception:
                pass
        # Stop the local lab if the scanner page started one.
        if scanner is not None and hasattr(scanner, "stop_lab"):
            try:
                scanner.stop_lab()
            except Exception:
                pass
        if demo is not None and getattr(demo, "_lab", None) is not None:
            try:
                stop_lab_server(demo._lab[0])
            except Exception:
                pass
        # Stop the backend only when this GUI started it; a backend the
        # user started elsewhere is left alone.
        if self.ctx.backend.running and self.ctx.backend.started_by_gui:
            try:
                self.ctx.backend.stop()
            except Exception:
                pass
        super().closeEvent(event)


def main(argv: list[str] | None = None) -> int:
    app = QApplication(argv or sys.argv)
    app.setApplicationName("CyberLLMv1 Security Lab")
    settings = load_settings(user_data_dir())
    ctx = AppContext.create(settings)
    window = MainWindow(ctx)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
