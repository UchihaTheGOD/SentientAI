# Development Log — `feature/cyberllm-desktop-portable`

Standing authorization (2026-10-28): autonomous, low-risk improvements on
this branch only. Hard limits: no other branch or repo, no force-push /
history rewrite / remote deletion, no merge to default, no public deploy
or release, no exe distribution, no deletion of user data, database,
weights, datasets, research files, or pre-existing changes, no secrets
in commits, no disabling auth/safety checks to pass tests, no paid
charges, no model retraining or replacement.

Environment note: work below is done in the Linux VM copy at
`~/workspace/sentientai-main-audit`, NOT the Windows PC copy at
`D:\AI TEST\SentientAI-portable`. Commits made here are local-only
until applied on Windows (patch files) or pushed; pushing from this VM
is auth-blocked (exit 128, no git credentials). The two evaluation
files (`evaluation/latest.json`, `evaluation/moderation_latest.json`)
are pre-existing working-tree churn and must NEVER be committed.

## 2026-10-28 — Milestone 1: desktop GUI audit fixes committed

- Commit `1fad93b` "Apply desktop GUI audit fixes" (3 files, +13/−8),
  user-approved 2026-10-28 16:55 IST ("Apply all three"):
  - `restart_server.ps1`: hard-coded dev-machine path replaced with
    `-ProjectPath` (defaults to `$PSScriptRoot`), trying `.venv`
    then `venv`.
  - `CYBERLLM_PORTABLE_SETUP.md`: torch CUDA 12.1 install step
    (torch deliberately not in `requirements.txt`; wheel supports
    Turing / compute 7.5).
  - `requirements-dev.txt`: stale `cyberllm_client.py` comment
    replaced with the accurate Starlette TestClient explanation.
- No code, test, or evaluation-file changes. Patch for Windows:
  `~/workspace/sentientai-audit-fixes-commit.patch` (outside repo).

## 2026-10-28 — Milestone 2: GUI backend venv resolution + build doc

- Bug: `security_lab/backend.py::find_backend_python` checked only
  `venv`, not `.venv` — the same class of bug as the `run.bat` fix.
  A frozen exe with a `.venv`-only project returned `None`
  (backend cannot start); from-source runs worked only by accident
  via the `sys.executable` fallback.
- Fix: try `.venv` first, then `venv`, matching `run.bat`/`run.sh`.
  The Windows exe path uses a forward-slash literal
  (`Scripts/python.exe`) because pathlib normalizes it on Windows
  and it keeps the layout testable on Linux.
- New regression tests: `security_lab/tests/test_backend_python.py`
  (7 tests: `.venv` preference, `venv` fallback, explicit setting
  wins / ignored when missing, frozen-without-venv returns `None`,
  source-without-venv returns current interpreter, Windows layout
  prefers `.venv`).
- Docs: `security_lab/packaging/BUILD_GUIDE.md` gains the torch
  CUDA 12.1 step (same gap class as the portable guide).
- Tests: lab suite **47 passed, 1 skipped** (was 40 passed + 1
  skipped on 41; +7 new; the skip is the pre-existing real-model
  smoke test, needs weights + `CYBERLLM_REAL_MODEL=1`). No app
  Python code changed and no app/root test imports
  `security_lab.backend`, so the root suite is unaffected by this
  milestone and was not rerun for it.
- Audit findings evaluated and NOT changed: no TODO/FIXME/XXX/HACK
  in `app/`, `security_lab/`, `scripts/`, `tests/`; the only
  dead-module reference is the intentional moderation-contract
  guard asserting `sentinel_moderation` is absent; `torch` /
  `peft` / `transformers` are deliberately absent from
  `requirements.txt` (large, platform-specific, loader handles
  missing torch); `psutil` is guarded, `pydantic` / `starlette` /
  `markupsafe` arrive transitively via fastapi/jinja2; `run.sh`
  start/test/status paths verified (`app.cli training-status`
  exists); `security_lab/README.md` defers backend setup to the
  build/portable guides, so no torch note added there.
  Approval-gated deletions left alone: tracked patch file,
  `TESTv1/training_factory/`, regenerable caches.
- NOT verified (Windows-only): exe build / double-click, `.venv`
  resolution on real Windows, GPU fit / latency, real 1.7B
  inference, Windows test run.
