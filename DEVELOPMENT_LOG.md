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

## 2026-10-28 — Milestone 3: release candidate 1.0.0-rc.1

- Baseline tests (Linux VM, this session): website 635 passed +
  1 skipped in 67.43s; Security Lab 47 passed + 1 skipped in 9.12s;
  0 failed in either suite. Skips are the known ones (template skip;
  real-model smoke).
- No prior versioning existed (no tags, no VERSION/CHANGELOG, no
  `__version__`): established `1.0.0-rc.1` as the first version.
  Deliberately NOT called stable: Windows/GPU/exe/real-inference
  verification is pending; promotion criteria are recorded in
  `CHANGELOG.md`.
- `VERSION`, `CHANGELOG.md` (with rollback procedure), README
  refresh: removed stale Sentinel claims and a duplicated §12
  (dual-model fusion text), corrected routers, stack, install,
  environment variables (added the real `CYBERLLM_*` rows),
  evaluation status, and the bootstrap-admin password literal
  (removed from docs; default remains in `manage.py` code).
- Correction during the README work: `Documentation/SENTIENTAI_AUDIT.md`
  exists (unusual name, not a typo for Sentinel) — its §23 link was
  briefly removed in error and immediately restored; the final
  README keeps it. Lesson: verify a file's existence before
  calling its link broken.
- Tag `v1.0.0-rc.1` (annotated) created on the release commit.
  Push outcome is recorded in the follow-up entry below.

## 2026-10-28 — Follow-up: release-candidate push outcome

- Push of `feature/cyberllm-desktop-portable` to origin attempted
  after all checks passed (diff reviewed, `git diff --check`
  clean, secrets scan clean, suites green, eval files unstaged).
  Result: FAILED, exit 128 — `fatal: could not read Username
  for 'https://github.com': No such device or address`. No git
  credentials exist in this VM, so the remote is untouched and the
  tag `v1.0.0-rc.1` remains local-only. The tag push was not
  attempted separately (it would fail identically).
- Delivery path remains patch files, in order after the
  desktop-portable replay: audit-fixes patch (`1fad93b`),
  milestone-2 patch (`bd19855`), release patch (this release
  commit), then this follow-up patch. The failed push attempt does
  not affect the user's planned Windows replay-push; if the user
  pushes their replay first, these local commits (different
  hashes, same content) reach that branch via patch application,
  not via fast-forward pull.

## 2026-10-28 — Milestone 4: hardening review + run.sh boot test (rc.2)

- Boundary re-verified first: repo `UchihaTheGOD/SentientAI`, branch
  `feature/cyberllm-desktop-portable`, HEAD `93185f5`, tag
  `v1.0.0-rc.1` still on `cda3462` (never moved), working tree only
  the 2 protected evaluation files modified-unstaged. Environment:
  Linux VM copy, NOT the Windows PC copy.
- Deep review read every Security Lab GUI page (control, scanner,
  model, users, reports, cases, demo, diagnostics, settings), the
  scanner engine + all 14 checks, backend integration, client auth
  boundary, and error paths. Real bugs fixed (each with a regression
  test); no unrelated rewrites; no app/ code touched.
- Fixes: backend failed-start process leak + log-handle leak;
  gpu_info multi-GPU/comma crash; scanner worker-thread widget
  update; stale scan-worker results; window-close scan stop;
  diagnostics scanner-safety always-fail; TRACE probe bypassing
  engine gates (+ corrected "GET only" claim); SSRF redirect
  substring false positive; TLS socket leak on handshake failure;
  case-store whole-file drop on one bad row; evaluation crash on
  mistyped expected label; unknown classification mislabelled as
  abstention; Control Center buttons stuck disabled on action
  error; demo simulation blocking the GUI thread; batch button not
  disabled; evaluation export open-dialog; baseline-save and
  own-login uncaught exceptions; users search per-keystroke HTTP;
  admin 401 leaving enabled-but-broken actions; settings-reset
  stale fields (Settings + Control Center showEvent refresh);
  local-lab start failures uncaught; settings bounds validation.
- Added: `run.sh` export/export-eval/backfill parity with `run.bat`;
  frozen-exe project-root discovery via exe parent's parent (the
  standard `<project>/dist/` layout); `build_windows.bat`
  `--upgrade` for GUI deps (Windows-untested batch change).
- Tests: Security Lab suite 86 passed + 1 skipped (87 total), up
  from 47 + 1 — 39 new regression tests, 0 failed. Website suite
  635 passed + 1 skipped (636 total), identical to rc.1.
- Boot test (clean Linux venv, created in repo `.venv` and removed
  after, with an empty `venv/` also present to prove `.venv`
  preference): deps installed (fastapi 0.115.6; torch absent by
  design); help lists 7 commands; missing-venv path exits 1 with
  instructions; `run.sh test tests/test_csrf.py` 5 passed via
  `.venv`; backend started as `.venv/bin/python run.py`; health
  ok; readiness honest `not_loaded`/`not_initialized`, device
  `cpu`, expected adapter SHA; second start failed honestly
  `[Errno 98]` (exit 1); SIGINT shutdown clean (reloader stopped,
  port closed, no `run.py` left); restart served health again;
  `run.sh status` printed counts (all 0); `run.sh backfill` dry-run
  `Would band 0 candidate(s)`. Export commands not executed (they
  write repo `data/` files); their `app.cli` signatures match
  `run.bat`. Qt system libs had been wiped by a VM replacement and
  were reinstalled (`apt-get update` + libegl1/libgl1/libxkbcommon0/
  libdbus-1-3/libfontconfig1) before the lab suite ran.
- Windows-blocker investigation (static, NOT verified): spec
  `datas=[]` is correct (no GUI resource files; `__main__.py` uses
  an absolute import, safe as a PyInstaller entry); the exe's
  project-root auto-detection gap is fixed above but the double-
  click itself is still untested; `build_windows.bat` checks for
  *a* python but not 3.11/3.12 specifically (wrong-version failure
  would surface honestly at pip install, not silently); the
  one-folder `COLLECT` fallback in BUILD_GUIDE remains the
  antivirus fallback. Still NOT verified on Windows: exe build +
  double-click, GPU fit/latency, real 1.7B inference, Windows test
  run, and the user's `unparseable` case (still awaiting raw output
  + truncated flag + token count).
- Known limitation (documented, not hidden): batch evaluation and
  single inference have no cancel; closing the window mid-batch or
  mid-inference does not stop the in-flight request (bounded by
  API timeouts; process exit ends them). Only scanner workers are
  stopped on close.
- Version: `1.0.0-rc.2` (VERSION, CHANGELOG, README updated; tag
  `v1.0.0-rc.2` to be created on the milestone commit). Still a
  release candidate: promotion to stable `v1.0.0` requires the
  Windows battery. `v1.0.0-rc.1` tag preserved, never moved.
- Push outcome is recorded in the follow-up entry below.
