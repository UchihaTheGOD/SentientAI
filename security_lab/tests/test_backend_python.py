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


def _make_venv(root, name, nt=None):
    """Create a fake venv python in ``root``.

    ``nt`` defaults to the HOST layout (``Scripts/python.exe`` on
    Windows, ``bin/python`` elsewhere). The old default was always
    the POSIX layout, so on Windows the helper built venvs the
    backend (which selects layout by runtime platform) never looks
    in — three tests failed there while passing on Linux.

    The path is built by a single assignment, never by branches
    that could leave it unassigned: a helper edited to add a layout
    branch without an ``else`` raises UnboundLocalError, which is
    exactly the failure a manual edit introduced on V2.
    """
    if nt is None:
        nt = os.name == "nt"
    exe_rel = "Scripts/python.exe" if nt else "bin/python"
    p = root / name / exe_rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("fake python", encoding="utf-8")
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


def test_discovery_is_rooted_in_given_project(tmp_path):
    """Discovery must never escape its given root to a real venv.

    Regression for the V2 failure mode where tests appeared to
    select the project's real .venv instead of the temporary test
    environment: whatever root is passed in, the returned python
    must live under that root.
    """
    other_root = tmp_path / "other"
    _make_venv(other_root, ".venv")
    dot_py = _make_venv(tmp_path, ".venv")
    found = find_backend_python(Settings(), tmp_path)
    assert found == dot_py
    assert tmp_path in found.parents
    assert found != other_root / ".venv" / (
        "Scripts/python.exe" if os.name == "nt" else "bin/python")
