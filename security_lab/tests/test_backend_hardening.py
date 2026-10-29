"""Hardening regressions: backend lifecycle, GPU reporting, frozen root."""

import os
import sys
from types import SimpleNamespace

from .. import backend as backend_mod
from ..backend import BackendManager, find_project_root, gpu_info
from ..config import Settings


class FakeProc:
    """Stand-in for subprocess.Popen (no real process is spawned)."""

    def __init__(self, *args, **kwargs):
        self.pid = 12345
        self._poll = None
        self.terminated = False
        self.killed = False

    def poll(self):
        return self._poll

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        self._poll = 0
        return 0


def _manager(monkeypatch, tmp_path, wait_ok):
    settings = Settings()
    manager = BackendManager(settings, tmp_path)
    monkeypatch.setattr(backend_mod, "find_project_root",
                        lambda s: tmp_path)
    monkeypatch.setattr(backend_mod, "find_backend_python",
                        lambda s, r: sys.executable)
    monkeypatch.setattr(BackendManager, "wait_ready",
                        lambda self, timeout=90: wait_ok)
    return manager


def test_failed_start_kills_backend_and_closes_log(monkeypatch, tmp_path):
    manager = _manager(monkeypatch, tmp_path, (False, "boom"))
    procs = []

    class RecordingProc(FakeProc):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            procs.append(self)

    monkeypatch.setattr("subprocess.Popen", RecordingProc)
    ok, msg = manager.start()
    assert ok is False
    assert "boom" in msg
    # A reported failure must not leave a running backend behind:
    # it would hold the port and confuse the next start.
    assert manager.proc is None
    assert manager.started_by_gui is False
    assert manager._log_handle is None
    assert procs and procs[0].terminated is True


def test_successful_start_marks_gui_owned(monkeypatch, tmp_path):
    manager = _manager(monkeypatch, tmp_path, (True, "ok"))
    monkeypatch.setattr("subprocess.Popen", FakeProc)
    ok, _msg = manager.start()
    assert ok is True
    assert manager.started_by_gui is True
    assert manager.proc is not None
    manager.stop()
    assert manager.proc is None


def test_launch_failure_closes_log_handle(monkeypatch, tmp_path):
    manager = _manager(monkeypatch, tmp_path, (True, "ok"))

    def boom(*args, **kwargs):
        raise OSError("no such python")

    monkeypatch.setattr("subprocess.Popen", boom)
    ok, msg = manager.start()
    assert ok is False
    assert "failed to launch" in msg
    assert manager._log_handle is None
    assert manager.proc is None


def test_gpu_info_multi_gpu_does_not_crash(monkeypatch):
    out = ("NVIDIA GeForce GTX 1660 SUPER, 6144 MiB, 100 MiB\n"
           "NVIDIA GeForce RTX 4090, 24576 MiB, 200 MiB\n")
    monkeypatch.setattr(
        "subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=out))
    info = gpu_info(None)
    assert info["available"] is True
    assert info["name"] == "NVIDIA GeForce GTX 1660 SUPER"


def test_gpu_info_comma_in_name_does_not_crash(monkeypatch):
    out = "NVIDIA Test, Pro Card, 8192 MiB, 0 MiB\n"
    monkeypatch.setattr(
        "subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=out))
    # A comma in the name breaks the three-field shape: gpu_info must
    # report "unavailable", never raise (its contract is never raises).
    info = gpu_info(None)
    assert info["available"] is False


def test_frozen_exe_in_dist_finds_project_root(monkeypatch, tmp_path):
    proj = tmp_path / "proj"
    (proj / "app").mkdir(parents=True)
    (proj / "run.py").write_text("")
    (proj / "app" / "main.py").write_text("")
    dist = proj / "dist"
    dist.mkdir()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        sys, "executable", str(dist / "CyberLLMv1-Security-Lab.exe"))
    monkeypatch.setattr(
        backend_mod, "__file__",
        str(tmp_path / "mei" / "security_lab" / "backend.py"))
    monkeypatch.setattr(os, "getcwd", lambda: str(dist))
    assert find_project_root(Settings()) == proj


def test_explicit_project_root_wins(monkeypatch, tmp_path):
    proj = tmp_path / "proj"
    (proj / "app").mkdir(parents=True)
    (proj / "run.py").write_text("")
    (proj / "app" / "main.py").write_text("")
    assert find_project_root(Settings(project_root=str(proj))) == proj
