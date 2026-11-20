"""Dialog helpers, kept in one module so tests can stub confirmations.

All destructive or role-changing GUI actions go through ``confirm``;
tests monkeypatch this module's functions instead of blocking on a
modal QMessageBox.
"""

from __future__ import annotations

from PySide6.QtWidgets import (QDialog, QDialogButtonBox, QInputDialog,
                               QMessageBox, QVBoxLayout, QWidget)


def confirm(parent: QWidget | None, title: str, text: str) -> bool:
    reply = QMessageBox.question(parent, title, text,
                                 QMessageBox.Yes | QMessageBox.No,
                                 QMessageBox.No)
    return reply == QMessageBox.Yes


def ask_text(parent: QWidget | None, title: str, label: str,
             default: str = "") -> str | None:
    text, ok = QInputDialog.getText(parent, title, label, text=default)
    return text if ok else None


def info(parent: QWidget | None, title: str, text: str) -> None:
    QMessageBox.information(parent, title, text)


def warn(parent: QWidget | None, title: str, text: str) -> None:
    QMessageBox.warning(parent, title, text)
