"""find_backend_python: .venv is tried before venv.

Regression tests for the venv-only resolution bug: a project with only
a .venv (the current layout) used to fall through to sys.executable,
or to None for a frozen exe, instead of using the project venv.
"""

import os
import sys
from pathlib import Path

from ..backend import find_backend_python
from ..config import Settings


def _make_venv(root, name, nt=False):
    if nt:
        p = root / name / "Scripts" / "python.exe"
    else:
        p = root / name / "bin" / "python"
    p.parent.mkdir(parents=True)
    p.write_text("fake python")
    return p


def test_dot_venv_preferred_over_venv(tmp_path):
    _make_venv(tmp_path, "venv")
    dot_py = _make_venv(tmp_path, ".venv")
    assert find_backend_python(Settings(), tmp_path) == dot_py


def test_venv_fallback_when_no_dot_venv(tmp_path):
    venv_py = _make_venv(tmp_path, "venv")
    assert find_backend_python(Settings(), tmp_path) == venv_py


def test_explicit_setting_wins(tmp_path):
    _make_venv(tmp_path, ".venv")
    custom = tmp_path / "custom" / "python"
    custom.parent.mkdir(parents=True)
    custom.write_text("fake python")
    assert find_backend_python(
        Settings(backend_python=str(custom)), tmp_path) == custom


def test_explicit_setting_ignored_when_missing(tmp_path):
    dot_py = _make_venv(tmp_path, ".venv")
    s = Settings(backend_python=str(tmp_path / "nope" / "python"))
    assert find_backend_python(s, tmp_path) == dot_py


def test_frozen_without_venv_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert find_backend_python(Settings(), tmp_path) is None


def test_source_without_venv_returns_current_interpreter(tmp_path,
                                                         monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert find_backend_python(Settings(), tmp_path) == Path(sys.executable)


def test_windows_layout_prefers_dot_venv(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "name", "nt")
    dot_py = _make_venv(tmp_path, ".venv", nt=True)
    _make_venv(tmp_path, "venv", nt=True)
    assert find_backend_python(Settings(), tmp_path) == dot_py
