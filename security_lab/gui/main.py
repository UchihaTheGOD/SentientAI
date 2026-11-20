"""Main window: sidebar navigation + stacked tool pages."""

from __future__ import annotations

import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QApplication, QListWidget, QMainWindow,
                               QScrollArea, QSplitter, QStackedWidget,
                               QWidget)

from ..config import Settings, load_settings, user_data_dir
from ..lab_server import stop_lab_server
from .context import AppContext
from .page_control import ControlCenterPage
from .page_misc import (CasesPage, DemoPage, DiagnosticsPage, ReportsPage,
                        SettingsPage)
from .page_model import ModelTestingPage
from .page_scanner import ScannerPage
from .page_testlab import TestLabPage
from .page_users import UserManagementPage
from .theme import DARK_STYLESHEET

PAGES = [
    ("control", "Website & Model Control Center"),
    ("scanner", "Authorized Website Security Scanner"),
    ("model", "Model Testing & Evaluation"),
    ("testlab", "Prompt & Output Test Lab"),
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
        # Minimum usable size: below this the window cannot shrink, so
        # controls are never clipped by the frame itself. Content below
        # the minimum is reached by scrolling (see QScrollArea below),
        # not by clipping. Do NOT use setFixedSize — the window must stay
        # resizable so native Windows Snap/maximize/restore keep working.
        self.setMinimumSize(900, 600)
        self.setStyleSheet(DARK_STYLESHEET)

        self.nav = QListWidget()
        self.stack = QStackedWidget()
        self._pages: dict[str, QWidget] = {}
        page_classes = {
            "control": ControlCenterPage,
            "scanner": ScannerPage,
            "model": ModelTestingPage,
            "testlab": TestLabPage,
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
            # Each page sits inside a scroll area so that, when the window
            # is made smaller or snapped to half-screen, the content scrolls
            # instead of clipping, overlapping, or disappearing. This is the
            # fix for the reported broken resizing/snapping: the window frame
            # was always a standard native QMainWindow (no frameless hint, no
            # custom drag code), but the pages had no scroll area, so their
            # content could not shrink below its minimum size hint.
            scroll = QScrollArea()
            scroll.setWidget(page)
            scroll.setWidgetResizable(True)
            self.stack.addWidget(scroll)
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
        # Stop a tunnel this app started, so it cannot outlive the window.
        control = self._pages.get("control")
        if control is not None and hasattr(control, "_stop_tunnel"):
            try:
                control._stop_tunnel()
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
    # DPI scaling must be set before the QApplication is created. Without
    # it, high-DPI displays can mis-scale the window and make the resize
    # borders hit-test incorrectly, which feels like broken dragging.
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(argv or sys.argv)
    app.setApplicationName("CyberLLMv1 Security Lab")
    settings = load_settings(user_data_dir())
    ctx = AppContext.create(settings)
    window = MainWindow(ctx)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
