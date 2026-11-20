# Changelog

All notable changes on the `feature/cyberllm-desktop-portable` branch.
Versioning follows semantic versioning. A `-rc.N` suffix marks a
release candidate: feature-complete for that release, but not yet
promoted to stable.

## [1.0.0-rc.2] — 2026-10-28

Hardening release candidate: a deep review of every Security Lab GUI
page, the scanner workflow, backend integration, the authentication
boundary, and error-handling paths, with real bugs fixed and
regression tests for each, plus a complete `run.sh` boot test in a
clean Linux virtual environment. Still a release candidate, not
stable: the Windows battery below is still pending, and the previous
candidate tag `v1.0.0-rc.1` is preserved (never moved).

Baseline tests (2026-10-28, Linux VM): website suite 635 passed +
1 skipped (636 total; skip = pre-existing template skip) —
identical to rc.1, no regressions. Security Lab suite 86 passed +
1 skipped (87 total; skip = real-model smoke, needs weights +
`CYBERLLM_REAL_MODEL=1`) — up from 47 + 1, with 39 new regression
tests for this milestone. 0 failed in either suite.

Boot test (2026-10-28, clean Linux venv, repo `.venv` created for
the test and removed after): dependencies installed from
`requirements.txt` + `requirements-dev.txt` (fastapi 0.115.6; torch
deliberately absent, import fails as designed); `run.sh` help lists
all 7 commands; missing-venv error path exits 1 with the setup
instructions; with both `.venv` (full) and `venv/` (empty) present,
`run.sh test` picked `.venv` (5 csrf tests passed); backend started
via `run.sh start` as `.venv/bin/python run.py`; health
`{"status":"ok","service":"sentientai"}`; readiness honest
`not_loaded` (`not_initialized`, device `cpu`, expected adapter
SHA); second start while running failed honestly with
`[Errno 98] Address already in use` (exit 1); SIGINT shutdown clean
(`Application shutdown complete`, reloader stopped, port closed, no
`run.py` processes remain); restart served health again;
`run.sh status` printed training-pipeline counts (all 0);
`run.sh backfill` dry-run reported `Would band 0 candidate(s)`.

### Fixed
- Backend start failure no longer leaks a running process: on a
  failed readiness wait the backend is stopped, the log handle is
  closed, and the next start does not report a phantom "already
  running" backend. A launch failure also closes the log handle.
- `gpu_info` no longer crashes on multi-GPU `nvidia-smi` output or
  on a GPU name containing a comma (first GPU reported; an
  unparseable line reports unavailable instead of raising), keeping
  its never-raises contract.
- Scanner progress no longer updates a widget from the worker
  thread: progress now crosses via the `ScanWorker.progress` signal.
  Late results from a superseded scan worker are ignored instead of
  overwriting a newer scan's results, and the worker reference is
  cleared on done/error. Closing the window stops any running scan.
- Diagnostics scanner-safety check no longer always fails: it
  expected `ScanRefused` from `Scanner.run()`, but `run()` reports
  refusals as errors in the returned result (only the unauthorized
  constructor raises). The check now inspects the result (0 requests
  + refusal error text), and a lab-server bind failure is reported
  instead of aborting the whole self-test.
- The TRACE misconfiguration probe no longer bypasses the scanner
  engine: it used `ctx.session.request` directly, skipping the
  request cap, deadline, stop event, rate limiter, and request
  accounting. It now uses the new gated `ScanContext.request_raw`.
  The "GET only" claim is corrected in the scanner limitations and
  the Scanner page (GET plus one read-only TRACE echo probe).
- SSRF open-redirect detection no longer matches by substring:
  `example.com.evil.com` was reported as an open redirect to
  `example.com`. It now compares the redirect hostname exactly
  (relative redirects are not external).
- TLS probe no longer leaks a socket when the handshake fails: the
  connected socket is closed before the error is reported.
- Case store no longer drops every case when one stored row is
  malformed: bad rows are skipped individually.
- Batch evaluation no longer crashes on a mistyped expected label
  (`KeyError` in the confusion matrix): labels outside the three
  classes are excluded from metrics but stay in the case list.
- Batch evaluation no longer mislabels a malformed API answer as an
  analyst abstention: an unexpected classification is now
  `predicted="error"` with an explanatory message.
- Control Center buttons no longer stay disabled when a backend
  action raises: the error path re-enables them.
- Demo simulation no longer blocks the GUI thread: rule screening
  and model calls run in a worker (a CPU inference used to freeze
  the window for minutes); failures still degrade to explicit
  "not measured" strings.
- Model page batch button is now disabled during a batch run and
  re-enabled on done/error; evaluation export now uses a save
  dialog (it used an open dialog); baseline-save failures and
  own-login exceptions are now reported instead of raising.
- User Management search no longer fires a synchronous HTTP request
  per keystroke (GUI freeze while typing): it is debounced 400 ms.
  An expired admin session (401) now disables the admin actions
  and asks for re-sign-in instead of leaving enabled buttons that
  all fail; the admin client maps 401 to `AuthError`.
- Settings reset no longer leaves stale form fields: the Settings
  page reloads its fields after reset, and the Control Center
  reloads its fields whenever it is shown, so a stale field cannot
  silently overwrite a newer saved value.
- Local-lab start failures on the Scanner and Demo pages are now
  reported in the page instead of raising out of the click handler.

### Added
- `run.sh` parity with `run.bat`: `export`, `export-eval`, and
  `backfill` commands (same `app.cli` signatures; `backfill` without
  `--apply` is a dry run). Help text lists all 7 commands. Export
  commands were not executed in the boot test (they write repo
  `data/` files); only `backfill` (dry run) was executed.
- Frozen-exe project-root discovery: a one-file build in
  `<project>/dist/` now also tries the exe directory's parent, so
  a double-clicked exe (cwd = `dist/`) auto-detects its project
  instead of reporting "project root not found". The BUILD_GUIDE
  first-run checklist (confirm project root in Control Center)
  remains the fallback.
- `build_windows.bat` now installs GUI deps with `--upgrade`, so a
  reused build venv cannot silently keep older packages than a
  fresh build would install. (Windows-untested: batch change only,
  not executed on Linux.)
- Diagnostics report check now writes its scratch files to a real
  temporary directory instead of littering the user data directory.

### Changed
- Settings validation: API port must be 1–65535 (Control Center and
  Settings pages); scan rate >= 0, timeout > 0, max requests >= 1,
  max workers >= 1 (Settings page). Invalid values are rejected
  with a message and leave saved settings unchanged.
- Scanner honesty text: the Scanner page and report limitations now
  state GET plus one read-only TRACE echo probe.

### Not verified (unchanged from rc.1)
- Windows test run, exe build + double-click, GPU fit/latency on the
  reference GTX 1660 SUPER, real 1.7B inference.
- The user's `unparseable` case diagnosis (awaiting raw output +
  truncated flag + token count).

## [1.0.0-rc.1] — 2026-10-28

Release candidate for the desktop-portable release. Verified on Linux
only (see "Not verified" below). Stable `v1.0.0` requires the Windows
battery: exe build + double-click, GPU fit/latency, real 1.7B
inference, Windows test run.

Baseline tests (2026-10-28, Linux VM): website suite 635 passed +
1 skipped (636 total; skip = pre-existing template skip); Security
Lab suite 47 passed + 1 skipped (48 total; skip = real-model smoke,
needs weights + `CYBERLLM_REAL_MODEL=1`). 0 failed in either suite.

### Added
- Native desktop Security Lab GUI (`security_lab/`, PySide6, 9 pages):
  Control Center, Authorized Scanner (14 detection-only categories),
  Model Testing & Evaluation, User Management, Reports & History,
  Cases, Demo/simulator (SIMULATED-labelled), Diagnostics, Settings.
- Admin users JSON API (`app/api/admin_users.py`): list/detail/role/
  activate/suspend/create/password-reset/audit-events, with
  backend-enforced guards (require_admin, no self role-change/
  deactivation/suspension, last-admin guard, token_version session
  invalidation). No delete endpoint; deactivation is the control.
- Portable runtime: `run.bat` (tries `.venv` then `venv`) and `run.sh`
  (Linux/macOS counterpart); project-local model layout
  `cyberLLMv1/{base,adapter}` + `scripts/setup_cyberllm.py --check`
  / `--download-base` / `--download-adapter` with adapter SHA
  verification.
- CyberLLMv1 as the single classifier (`app/services/classifier.py`):
  rules 50% + confident model 50%, SSRF/metadata deterministic
  override, unavailable/unparseable/truncated/mismatch/
  unjustified-threat → `needs_review`; moderation is human-only.
- Versioning: `VERSION`, this changelog, `DEVELOPMENT_LOG.md`,
  annotated tag `v1.0.0-rc.1`, and the rollback procedure below.
- Release reports: `reports/ARCHITECTURE_AUDIT.md`,
  `CLEANUP_REPORT.md`, `CYBERLLM_INTEGRATION_REPORT.md`,
  `TEST_RESULTS.md`, `PORTABILITY_REPORT.md`, `RELEASE_READINESS.md`.

### Changed
- `/api/sentinel/analyze` no longer returns `model_a`/`model_b`/
  `agreement`/`prompt` and no longer accepts `extra_prompt`;
  readiness reports classifier `cyberllm`; prompt status/reload
  routes removed (404).
- Reports list/detail UI migrated to single-CyberLLMv1 presentation
  (API storage-mirror `model_a_*`/`model_b_*` fields kept for
  historical rows).
- Loader diagnostics: artifact validation now runs before the
  missing-torch check, so an incomplete model dir reports its own
  error even in a torch-less venv.
- Promotion/rollback subprocess tests inherit the parent env and
  override only `CYBERLLM_MODEL_ROOT` (fixes a Windows
  WinError-10106-class failure); portability `D:` assertion replaced
  with a project-tree check; test file reads use UTF-8 explicitly
  (fixes Windows CP1252 failures).
- GUI backend venv resolution: `.venv` tried before `venv`
  (was `venv`-only; a frozen exe with a `.venv`-only project
  returned `None`).
- README refreshed for the current branch (removed stale Sentinel
  claims and a duplicated section, corrected routers, stack,
  install, environment, and evaluation status).

### Removed
- Obsolete Sentinel model code: `sentinel_loader`,
  `sentinel_inference`, `sentinel_moderation`, `sentinel_schema`,
  `sentinel_fusion`, `prompt_service`, `sentinel_model.py`, root
  `config.py`, `prompts/prompt.txt`, old-model tests.
- Dead lab-runner duplicates and root scratch scripts; stale
  duplicate README section 12 (dual-model fusion text).

### Fixed
- `restart_server.ps1` stale hard-coded dev-machine path →
  `-ProjectPath` parameter (defaults to the script folder),
  `.venv` then `venv`.
- Torch install step added to `CYBERLLM_PORTABLE_SETUP.md` and
  `security_lab/packaging/BUILD_GUIDE.md` (torch deliberately not in
  `requirements.txt`).
- Stale `requirements-dev.txt` comment referencing deleted
  `cyberllm_client.py` → accurate Starlette TestClient explanation.
- Bootstrap admin password literal removed from the README (the
  default remains in `manage.py` code; change it after first login).

### Security
- Scanner: authorization confirmation + allowlist required; localhost,
  private-network, and cloud-metadata destinations blocked by default;
  GET-only read-only checks; evidence redaction (credentials, cookies,
  tokens never stored); findings distinguish suspected / verified /
  inconclusive — a missing header, error, or version string alone
  never confirms a vulnerability.
- Admin actions enforced on the backend, not merely hidden in the GUI.
- No secrets, weights, local databases, or `.env` contents are
  committed (see `.gitignore`).

### Not verified (Windows / hardware only)
- Windows test run, exe build + double-click, GPU fit/latency on the
  reference GTX 1660 SUPER, real 1.7B inference.
- The user's `unparseable` case diagnosis (awaiting raw output +
  truncated flag + token count).

## Rollback

- In any clone containing the tags: `git checkout v1.0.0-rc.2` for
  the current candidate, or `git checkout v1.0.0-rc.1` for the
  previous one. Return with
  `git checkout feature/cyberllm-desktop-portable`. Stash or commit
  working-tree changes first; never check out over uncommitted files
  you need — back them up first. The two evaluation files
  (`evaluation/latest.json`, `evaluation/moderation_latest.json`)
  are uncommitted working-tree churn, not part of any release.
- On a Windows PC without the tags: apply the patch chain in order —
  desktop-portable patches (`c542cc7..0a5d052`), audit-fixes patch
  (`1fad93b`), milestone-2 patch (`bd19855`), the rc.1 release
  patch, the rc.1 push-record patch, then the rc.2 hardening patch
  — or fetch the branch/tags from origin once pushed.
- Code rollback does NOT touch model weights (outside the repo),
  the SQLite database (gitignored), or `.env`. Back those up
  separately before destructive actions (`manage.py reset-db --yes`
  destroys the database).
- Never move the tags (`v1.0.0-rc.1`, `v1.0.0-rc.2`). To supersede
  them, create a new version (e.g. `1.0.0-rc.3` or stable `1.0.0`
  once the Windows battery passes).

## [Unreleased]

- (none yet)
