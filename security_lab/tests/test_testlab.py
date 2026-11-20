"""Tests for the Prompt & Output Test Lab page (security_lab/gui/page_testlab.py).

The JSON-validity helper is pure logic (no GUI). The page-construction
test uses the offscreen Qt platform; it verifies the page builds and
registers its controls without launching a window. No network, no model.
"""

import json

import pytest

from security_lab.gui.page_testlab import _json_validity

FULL = {
    "summary": "x", "classification": "likely_benign", "confidence": "high",
    "indicators": [], "reasoning": "r", "limitations": [],
    "recommended_actions": [],
}


def test_json_valid_full_object():
    ok, detail = _json_validity(json.dumps(FULL))
    assert ok is True
    assert "all 7 required keys" in detail


def test_json_invalid_syntax():
    ok, detail = _json_validity("{bad json")
    assert ok is False
    assert "invalid JSON" in detail


def test_json_valid_but_missing_keys():
    ok, detail = _json_validity(json.dumps({"summary": "x"}))
    assert ok is False
    assert "missing keys" in detail
    assert "classification" in detail


def test_json_valid_but_not_object():
    ok, detail = _json_validity("[1, 2]")
    assert ok is False
    assert "not an object" in detail


def test_json_empty_string_invalid():
    ok, _ = _json_validity("")
    assert ok is False


def test_page_builds_offscreen(tmp_path, monkeypatch):
    """The Test Lab page constructs without a window and shows its controls."""
    pytest.importorskip("PySide6")
    import os
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    from security_lab.config import Settings
    from security_lab.gui.context import AppContext
    from security_lab.gui.page_testlab import TestLabPage

    app = QApplication.instance() or QApplication([])
    settings = Settings()
    ctx = AppContext.create(settings, data_dir=tmp_path)
    page = TestLabPage(ctx)
    assert page.cb_kind.count() == 4
    assert page.sp_max_tokens.minimum() == 16
    assert page.sp_max_tokens.maximum() == 512
    assert page.btn_run.text() == "Run test"
    assert page.tbl.columnCount() == 6
    page.close()
