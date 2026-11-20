# SentientAI Test Results

Branch: `feature/cyberllm-desktop-portable` (code commit `8a5aee9`).
All counts below are from runs on this branch, in this VM, after the
fixes were applied — except where a row says otherwise. Commands are
reproducible from the repo root.

## 1. Environments

- VM: 2 CPUs, ~7.7 GB RAM, **no GPU**, ~90 GB free disk.
- System Python 3.12.3. Backend venv `~/workspace/venvs/sentientai/`
  (FastAPI/SQLAlchemy import OK; **torch is NOT installed** — this is
  why the portability test for missing torch is meaningful here).
- GUI venv `~/workspace/venvs/security-lab/` (pytest 9.1.1, PySide6
  6.12.0, reportlab 5.1.0; Qt offscreen via `QT_QPA_PLATFORM=offscreen`).
- Real-model tests are isolated from fast unit tests by design: the
  real-model smoke skips unless `CYBERLLM_REAL_MODEL=1` and the backend
  reports ready.

## 2. Tests fixed on this branch (targeted run)

Command: backend venv `pytest tests/test_cyberllm_portability.py
tests/test_cyberllm_feedback.py tests/test_learning_workflow_e2e.py
tests/test_sentinel_moderation_contract.py tests/test_cyberllm_api.py
tests/test_e2e_and_security.py -q`

| Test area | Before (this branch's audit) | After |
|---|---|---|
| Portability: incomplete base dir (`test_present_but_incomplete_base_fails_clearly`) | FAILED — reported "PyTorch is not installed" instead of "base config.json missing" / "incomplete", because the loader checked torch before artifacts | PASSED (loader validates artifacts first; test unchanged) |
| Portability: default root (`test_default_root_is_project_local_not_cwd`) | Would FAIL on any Windows machine where the project lives on `D:` (assertion `"D:" not in str(paths.root)`) | PASSED (project-tree membership assertion; project-local equality assertion unchanged) |
| Promotion / rollback subprocess tests (feedback + e2e, 6 call sites) | Would FAIL on Windows with a stripped Linux-only env (`PATH=/usr/bin:/bin`, no SystemRoot — WinError 10106 family) | PASSED (parent env inherited, only `CYBERLLM_MODEL_ROOT` overridden) |
| Moderation contract + 2 UTF-8 reads | Would FAIL on Windows (locale CP1252 decoding of UTF-8 sources containing em-dashes/curly quotes) | PASSED (`read_text(encoding="utf-8")`; moderation test also repo-root-relative now) |

**Targeted total: 43 passed, 0 failed.** No test was deleted or weakened
to obtain this: one production diagnostic order changed (loader), one
over-broad assertion was replaced by a precise one (portability), and
the rest are environment-handling fixes in test code.

## 3. Full website test suite

Command: backend venv `pytest -q` → log `/tmp/full_root_suite.log`
(kept outside the repo).

- **636 collected, 635 passed, 0 failed, 1 skipped.**
- The 1 skip is the pre-existing template skip, unchanged.
- Previous branch state was 634 passed, 1 failed (the portability test
  above), 1 skipped — the failure is fixed, nothing else regressed.
- Note on counting: this pytest setup does not print a final counts
  line in `-q` output; totals were established from the summary line
  (`635 passed, 1 skipped`) and per-file collection counts summing to
  636.

## 4. Desktop GUI test suite

Command: GUI venv `pytest security_lab/tests -q`.

- **41 collected, 40 passed, 0 failed, 1 skipped.**
- The 1 skip is `test_real_model_smoke.py`: it skips honestly unless
  `CYBERLLM_REAL_MODEL=1` and the backend reports ready. No weights
  exist in this VM, so the skip is the correct outcome, not a gap in
  coverage.
- Split receipts (both clean): non-GUI tests 36 passed, 1 skipped;
  GUI smoke file 4 passed.
- Correction to the previous branch's report: it stated "41 passed,
  1 skipped, 42 total". The suite collects 41 tests, so the correct
  figures are 40 passed, 1 skipped, 41 total. The suite itself is
  unchanged on this branch; only the count was miscounted before.
- Teardown note: one full-suite run exited 139 (SIGSEGV) *after* all
  41 tests had completed with passing marks, during Qt offscreen
  teardown, before pytest wrote its summary. The split runs above give
  clean summaries for the same tests, so this is a VM Qt-teardown
  artifact, not a test failure. It is recorded here rather than hidden.

## 5. GUI + backend smoke (live, this branch)

Script `/tmp/desktop_smoke.py` (outside the repo), GUI venv, offscreen:

- Backend started via `BackendManager` (real uvicorn, pid 22399) with
  the backend venv Python on `127.0.0.1:8124`.
- Readiness answered honestly: `ready: False, state: not_loaded,
  reason: not_initialized`, base `Qwen/Qwen3-1.7B`, adapter SHA
  `d624ed79…5a5b1`, device `cpu`, quantization `none`.
- Backend stopped cleanly (`running: False` after stop).
- Full GUI constructed offscreen: **9 pages** (Control Center, Scanner,
  Model Testing, User Management, Reports, Cases, Demo, Diagnostics,
  Settings). No window was shown; this VM has no display server.

## 6. Static checks (this branch)

- `node --check app/static/js/security_reports.js`: OK.
- Jinja parse of `admin_reports_security_detail.html` and
  `admin_reports_security.html`: OK (catches `{% if %}` / `{% endif %}`
  imbalance from the Model B conditional).
- `bash -n run.sh`: OK. `./run.sh` from the repo (no venv present):
  clean error naming both `.venv` and `venv` and the creation commands.
- `run.bat` line endings preserved as CRLF (verified with `file`).

## 7. Results carried over unchanged from `dcf7c2b` (code untouched)

- Lab scan smoke (real run, local mock lab): 31 requests, **14
  findings, 0 errors** (`.env` High/suspected with body never stored;
  reflection Low/suspected; 5 missing headers; no-cookies
  informational). Scanner code is unchanged on this branch, so this
  result stands; it was not re-run here.
- Admin API suite: 19 tests in `tests/test_admin_users_api.py`, all
  passing (included in the 635 above).

## 8. Explicitly NOT verified (no claim is made)

- **Real 1.7B inference on this branch in this VM**: blocked — no
  weights, no torch. Last real inference: 2026-10-24 CPU runs (see
  CYBERLLM_INTEGRATION_REPORT §6). The smoke test above proves the
  honest `not_loaded` path, not inference.
- **Windows exe build and double-click launch**: not built or tested
  here (this VM is Linux). Build via `security_lab/packaging/
  build_windows.bat` + `BUILD_GUIDE.md` on a Windows PC; the spec
  parses and the GUI builds offscreen, but the exe itself is unverified.
- **GPU fit / latency on GTX 1660 SUPER 6 GB**: unmeasured estimate
  (~4.5 GB peak) only; the 8-bit and CPU fallbacks are the documented
  ladder.
- **Linux venv start path beyond the error path**: `run.sh` start/test
  were syntax-checked and error-path-checked, but no repo-local venv
  exists in this VM to boot the app through `run.sh` end to end.
- **Windows test runs**: the fixes target the three known Windows
  failure modes by construction (env inheritance, drive-letter
  neutrality, UTF-8 reads), but they were executed on Linux; a Windows
  run of `run.bat test` is still the confirming step.
