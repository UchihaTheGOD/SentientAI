"""QThread workers: long work never blocks the UI thread.

Each worker emits finished/error signals; the page updates widgets
only from those signal handlers (the Qt thread-safe path).
"""

from __future__ import annotations

from typing import Any, Callable

from PySide6.QtCore import QThread, Signal


class ScanWorker(QThread):
    progress = Signal(int, int, str)
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, make_scanner: Callable[[], Any], parent=None):
        super().__init__(parent)
        self._make_scanner = make_scanner
        self.scanner = None

    def run(self) -> None:
        try:
            self.scanner = self._make_scanner()
            result = self.scanner.run()
            self.finished.emit(result)
        except Exception as exc:
            self.error.emit(str(exc))

    def stop_scan(self) -> None:
        if self.scanner is not None:
            try:
                self.scanner.ctx.stop()
            except Exception:
                pass


class InferenceWorker(QThread):
    finished = Signal(dict)
    error = Signal(str)

    def __init__(self, fn: Callable[[], dict], parent=None):
        super().__init__(parent)
        self._fn = fn

    def run(self) -> None:
        try:
            self.finished.emit(self._fn())
        except Exception as exc:
            self.error.emit(str(exc))


class DiagnosticsWorker(QThread):
    progress = Signal(str)
    finished = Signal(list)
    error = Signal(str)

    def __init__(self, fn: Callable[[Callable[[str], None]], list],
                 parent=None):
        super().__init__(parent)
        self._fn = fn

    def run(self) -> None:
        try:
            self.finished.emit(self._fn(self.progress.emit))
        except Exception as exc:
            self.error.emit(str(exc))


class BackendWorker(QThread):
    finished = Signal(bool, str)
    error = Signal(str)

    def __init__(self, fn: Callable[[], tuple[bool, str]], parent=None):
        super().__init__(parent)
        self._fn = fn

    def run(self) -> None:
        try:
            ok, msg = self._fn()
            self.finished.emit(ok, msg)
        except Exception as exc:
            self.error.emit(str(exc))


class BatchWorker(QThread):
    progress = Signal(int, int)
    finished = Signal(object)
    error = Signal(str)

    def __init__(self, fn: Callable[[Callable[[int, int], None]], object],
                 parent=None):
        super().__init__(parent)
        self._fn = fn

    def run(self) -> None:
        try:
            self.finished.emit(self._fn(self.progress.emit))
        except Exception as exc:
            self.error.emit(str(exc))
