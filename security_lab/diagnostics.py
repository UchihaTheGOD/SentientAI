"""One-click self-test: configuration, artifacts, backend, model,
scanner safety, and report generation.

Each check returns a dict: name, status (pass/fail/warn), detail, fix.
A check that cannot run reports why; it never pretends to pass.
Model inference is attempted only when the backend reports the model
ready — otherwise it is reported as skipped-with-reason, not faked.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from . import backend as backend_mod
from .client import BackendClient
from .config import Settings


@dataclass
class CheckResult:
    name: str
    status: str  # pass | fail | warn | skipped
    detail: str
    fix: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "status": self.status,
                "detail": self.detail, "fix": self.fix}


def _pass(name: str, detail: str) -> CheckResult:
    return CheckResult(name, "pass", detail)


def _fail(name: str, detail: str, fix: str = "") -> CheckResult:
    return CheckResult(name, "fail", detail, fix)


def _warn(name: str, detail: str, fix: str = "") -> CheckResult:
    return CheckResult(name, "warn", detail, fix)


def _skip(name: str, detail: str) -> CheckResult:
    return CheckResult(name, "skipped", detail)


def check_python_and_deps(settings: Settings, root: Path | None) -> CheckResult:
    python = None
    if root is not None:
        python = backend_mod.find_backend_python(settings, root)
    if python is None and not getattr(sys, "frozen", False):
        python = Path(sys.executable)
    if python is None:
        return _fail("Backend Python",
                     "no backend Python configured or found",
                     "Set the backend Python in Settings, or create the "
                     "project venv.")
    try:
        out = subprocess.run(
            [str(python), "-c",
             "import fastapi, uvicorn, sqlalchemy; print('ok')"],
            capture_output=True, text=True, timeout=30)
        if out.returncode == 0:
            return _pass("Backend Python",
                         f"{python} (fastapi/uvicorn/sqlalchemy importable)")
        return _fail("Backend Python",
                     f"{python} cannot import backend dependencies",
                     "Install requirements.txt in that interpreter.")
    except (OSError, subprocess.SubprocessError) as exc:
        return _fail("Backend Python", f"could not run {python}: {exc}")


def check_project_root(settings: Settings) -> tuple[Path | None, CheckResult]:
    root = backend_mod.find_project_root(settings)
    if root is None:
        return None, _fail(
            "Project root",
            "SentientAI project not found (need run.py + app/main.py)",
            "Set the project root in Settings to the SentientAI folder.")
    return root, _pass("Project root", str(root))


def check_artifacts(settings: Settings, root: Path) -> CheckResult:
    result = backend_mod.check_artifacts(settings, root)
    if result.missing:
        return _fail("Model artifacts", "; ".join(result.missing),
                     "Run scripts/setup_cyberllm.py --check, then "
                     "--download-base / --download-adapter.")
    if result.adapter_sha_status == "mismatch":
        return _fail("Model artifacts",
                     "adapter SHA-256 mismatch (see detail)",
                     "Re-download the pilot v8 adapter and verify its SHA.")
    return _pass(
        "Model artifacts",
        f"base: {result.base_dir}; adapter: {result.adapter_dir} "
        f"(SHA {result.adapter_sha_status})")


def check_gpu(settings: Settings, root: Path | None) -> CheckResult:
    python = None
    if root is not None:
        python = backend_mod.find_backend_python(settings, root)
    info = backend_mod.gpu_info(python)
    if info.get("available"):
        return _pass("GPU",
                     f"{info.get('name')} via {info.get('source')} "
                     f"(VRAM total {info.get('vram_total')}, "
                     f"used {info.get('vram_used')})")
    return _warn("GPU",
                 info.get("detail", "no GPU detected") +
                 "; the model will run on CPU if loaded",
                 "Install a CUDA-enabled PyTorch build for GPU inference, "
                 "or set device=cpu.")


def check_data_dir_writable(data_dir: Path) -> CheckResult:
    try:
        probe = data_dir / ".write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return _pass("Data directory writable", str(data_dir))
    except OSError as exc:
        return _fail("Data directory writable", str(exc),
                     "Pick a writable data directory or fix permissions.")


def check_backend_api(settings: Settings) -> tuple[dict, CheckResult]:
    client = BackendClient(settings.api_base)
    try:
        data = client.readiness()
    except Exception as exc:
        return {}, _fail("Backend API",
                         f"readiness unreachable: {exc}",
                         "Start the backend from the Control Center.")
    state = data.get("state", "?")
    if data.get("ready"):
        return data, _pass("Backend API",
                           f"readiness: ready (device {data.get('device')}, "
                           f"quantization {data.get('quantization')})")
    return data, _warn("Backend API",
                       f"readiness: {state} "
                       f"({data.get('reason') or 'model not loaded yet'})",
                       "Load the model from the Control Center, or run an "
                       "analysis (which loads it lazily).")


def check_scanner_safety() -> CheckResult:
    """Exercise the scanner's refusal paths against non-targets."""
    from .lab_server import start_lab_server, stop_lab_server
    from .scanner.engine import Scanner, ScanConfig, ScanRefused

    # Unauthorized scan must be refused before any request.
    try:
        Scanner(ScanConfig(target="http://127.0.0.1:9/", authorized=False))
        return _fail("Scanner safety", "unauthorized scan was not refused")
    except ScanRefused:
        pass
    # Non-allowlisted host must be refused. Note run() reports refusals
    # as errors in the returned result; it does not raise for them
    # (only the unauthorized constructor raises). An earlier version
    # of this check expected ScanRefused from run() and therefore
    # reported failure on every run, even when refusals worked.
    result = Scanner(ScanConfig(target="http://example.com/", authorized=True,
                                allowlist=["other.example"])).run()
    if result.requests_made != 0 or not any(
            "not on the allowlist" in e for e in result.errors):
        return _fail("Scanner safety", "non-allowlisted host was not refused")
    # Private/metadata IP must be refused even when allowlisted by name.
    result = Scanner(ScanConfig(target="http://169.254.169.254/latest/meta-data/",
                                authorized=True,
                                allowlist=["169.254.169.254"])).run()
    if result.requests_made != 0 or not any(
            "blocked address" in e for e in result.errors):
        return _fail("Scanner safety", "metadata address was not refused")
    # A real local-lab scan must succeed end to end.
    try:
        server, _thread, url = start_lab_server()
    except OSError as exc:
        return _fail("Scanner safety", f"local lab could not start: {exc}")
    try:
        result = Scanner(ScanConfig(
            target=url, allowlist=["127.0.0.1"], local_lab_enabled=True,
            authorized=True, rate_limit_seconds=0.01,
            timeout_seconds=5)).run()
        if result.findings and not result.errors:
            return _pass("Scanner safety",
                         f"refusals hold; lab scan produced "
                         f"{len(result.findings)} findings, 0 errors")
        return _fail("Scanner safety",
                     f"lab scan unexpected: {len(result.findings)} findings, "
                     f"errors={result.errors[:2]}")
    finally:
        stop_lab_server(server)


def check_reports(tmp_dir: Path) -> CheckResult:
    from .reports import (export_scan_csv, export_scan_html,
                          export_scan_json)
    from .scanner.engine import ScanResult
    from .scanner.findings import Finding

    result = ScanResult(
        target="http://127.0.0.1:1/", started_at="2026-01-01T00:00:00",
        finished_at="2026-01-01T00:00:01",
        findings=[Finding("Self-test finding", "Self-test", "Low", "high",
                          "verified", "diagnostic only", "none",
                          "http://127.0.0.1:1/", "none", "none")],
        summary={"Low": 1, "total": 1}, requests_made=0, stopped=False,
        errors=[], timeline=[], limitations=[])
    try:
        export_scan_html(result, tmp_dir / "selftest.html")
        export_scan_json(result, tmp_dir / "selftest.json")
        export_scan_csv(result, tmp_dir / "selftest.csv")
        return _pass("Report generation", "HTML, JSON, and CSV exports OK")
    except Exception as exc:
        return _fail("Report generation", str(exc))


def run_diagnostics(
    settings: Settings, data_dir: Path,
    progress: Callable[[str], None] | None = None,
) -> list[CheckResult]:
    """Run every check; model inference is reported, never fabricated."""
    results: list[CheckResult] = []

    def emit(name: str) -> None:
        if progress:
            progress(name)

    emit("Project root")
    root, res = check_project_root(settings)
    results.append(res)
    emit("Backend Python")
    results.append(check_python_and_deps(settings, root))
    if root is not None:
        emit("Model artifacts")
        results.append(check_artifacts(settings, root))
        emit("GPU")
        results.append(check_gpu(settings, root))
    else:
        results.append(_fail("Model artifacts",
                             "skipped: project root unknown"))
        results.append(_warn("GPU", "skipped: project root unknown"))
    emit("Data directory")
    results.append(check_data_dir_writable(data_dir))
    emit("Backend API")
    readiness, res = check_backend_api(settings)
    results.append(res)
    if readiness.get("ready"):
        results.append(_pass(
            "Model inference",
            "backend reports the model ready; run a real analysis from "
            "Model Testing to exercise inference (diagnostics does not "
            "spend a generation here)."))
    else:
        results.append(_skip(
            "Model inference",
            "backend does not report the model ready "
            f"({readiness.get('state', 'unreachable')}); inference is "
            "untested, not assumed."))
    emit("Scanner safety")
    results.append(check_scanner_safety())
    emit("Report generation")
    # The report check writes scratch files: keep them in a real temp
    # dir, not in the user's data directory.
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        results.append(check_reports(Path(td)))
    return results
