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

## 2026-10-28 — Follow-up: release-candidate 1.0.0-rc.2 push outcome

- Push of `feature/cyberllm-desktop-portable` to origin attempted
  after all checks passed (diff reviewed, `git diff --check`
  clean, secrets/weights/DB scan clean, suites green, eval files
  unstaged, tag `v1.0.0-rc.2` on the milestone commit).
  Result: FAILED — `fatal: could not read Username for
  'https://github.com': No such device or address`. No git
  credentials exist in this VM, so the remote is untouched and
  both tags (`v1.0.0-rc.1`, `v1.0.0-rc.2`) remain local-only. The
  tag push was not attempted separately (it would fail
  identically).
- Delivery path remains patch files, in order after the
  desktop-portable replay: audit-fixes patch (`1fad93b`),
  milestone-2 patch (`bd19855`), rc.1 release patch, rc.1
  push-record patch, then the rc.2 hardening patch (this
  milestone commit) and this push-record patch. If the user pushes
  their replay first, these local commits (different hashes, same
  content) reach that branch via patch application, not via
  fast-forward pull.

## 2026-10-28 — Follow-up: rc.2 delivery completion attempt (user-directed)

- Verification first, before any action. Repository
  `https://github.com/UchihaTheGOD/SentientAI`, branch
  `feature/cyberllm-desktop-portable`, tip `c5691e6` (rc.2
  push-record). Tag `v1.0.0-rc.2` verified to point at
  `f086a64` (`f086a64df93ac0405e3c17a9c43f2aa239be72cf`);
  tag `v1.0.0-rc.1` still on `cda3462`. Neither tag was moved,
  and no history was rewritten. Working tree: only
  `evaluation/latest.json` and `evaluation/moderation_latest.json`
  modified-unstaged, as before; neither was staged, committed,
  or restored.
- Evaluation-file hash note (no action taken): the current
  working-tree hashes (`2b6ee3d0…` /
  `5fe51b9a…`) differ from the 2026-10-27 record
  (`7fb612b5…` / `61a10731…`). Cause confirmed in code, not
  assumed: `tests/test_evaluation_matrix.py` and
  `tests/test_sentinel_moderation_contract.py` call
  `run_evaluation(..., output_dir="evaluation")`, which rewrites
  both files on every root-suite run; mtimes
  (2026-10-28 14:36 UTC) match the last suite run. This is
  test-regenerated churn, not user data loss, and the files
  stay uncommitted by rule.
- Remote check (unauthenticated read of the public repo):
  remote branch `feature/cyberllm-desktop-portable` EXISTS at
  `dd22172` ("Add desktop-portable release reports", committed
  on the PC 2026-10-28 11:34 IST). Its tree hash
  (`34e79dc8…`) is IDENTICAL to local `0a5d052`: the user has
  pushed the desktop-portable base replay. Remote `main` is
  still `c542cc7`, untouched. Remote tag `v1.0.0-rc.2` does NOT
  exist.
- Consequence: the milestone chain (`1fad93b`, `bd19855`,
  `cda3462`, `93185f5`, `f086a64`, `c5691e6`) is NOT on the
  remote, and the remote tip is neither an ancestor nor a
  descendant of the local tip (replay divergence: same content
  at the base, different commit objects). Nothing was
  force-pushed or rebased to reconcile this; the user's remote
  replay is the remote truth for that branch.
- Push re-attempted from this VM and blocked again, same as
  every prior attempt: `git push --dry-run` for both the branch
  and the tag fails with `fatal: could not read Username for
  'https://github.com': No such device or address`. Cause
  re-verified, not assumed: no git credential helper is
  configured, `gh` is installed but not logged into any host,
  and SSH from this VM is blocked at the egress proxy
  (connection reset by the proxy) — so adding an SSH key alone
  would not unblock pushes from here. The remote was not
  modified by these checks.
- GitHub connector assessed and deliberately NOT used for
  this delivery: it is connected and authenticated, but its
  toolset (`create_branch`, `push_files`,
  `create_or_update_file`) can only create new snapshot
  commits from file contents. It cannot push the existing
  local commit objects, and it has no tag-creation tool, so it
  cannot publish `v1.0.0-rc.2` pointing at `f086a64`. A
  snapshot delivery would produce a third divergent history
  and would conflict with the user's patch-chain replay, so it
  was left alone. Supported auth options that do NOT involve
  pasting a token into chat: (1) `gh auth login` device flow
  completed by the user in their own browser/terminal;
  (2) pushing from the Windows PC, which is already proven
  (the base replay is on the remote); the milestone patches
  already delivered with the rc.2 report apply on top of the
  remote tip in order. Note on the tag: a tag published from
  a PC replay would point at the replayed rc.2-equivalent
  commit (content-identical tree, different hash), not at
  `f086a64`, because `f086a64` does not exist on the remote;
  publishing the local tag object itself requires a real git
  push of the local objects.
- Windows environment: none accessible from this VM.
  Tailscale reports "Not connected", and no remote access to
  the user's PC was ever authorized. No Windows file was
  modified by this session; everything below stays pending
  for the PC: Windows test run, exe build + double-click,
  GPU fit/latency on the GTX 1660 SUPER, real 1.7B inference,
  and the user's unparseable-case details (raw output +
  truncated flag + output_tokens). Nothing in this entry
  claims any Windows result.
- Remaining delivery step (PC side, patches already in the
  user's hands): apply audit-fixes, milestone-2, rc.1
  release, rc.1 push-record, rc.2 hardening, rc.2
  push-record patches in order on top of remote `dd22172`,
  push the branch, then tag the replayed rc.2-equivalent
  commit and push the tag. Until that happens, `v1.0.0-rc.2`
  is a local-only tag and the milestone commits are
  local-only.

## 2026-10-29 — Follow-up: milestone chain published as real Git commits (no patches)

- The user asked to stop using patch files as the delivery method
  and to put actual Git commits on GitHub. Delivered via the
  authorized GitHub connector (MCP `push_files`), because git
  push from this VM is still auth-blocked (no credential
  helper, `gh` not logged in, SSH blocked at the egress
  proxy) and the connector doc forbids starting a separate
  `gh auth login` / device / PAT flow. No token was pasted,
  requested, or committed.
- Base verified live before publishing: remote branch
  `feature/cyberllm-desktop-portable` at `dd22172` (the user's
  Windows replay, clean tree), remote `main` untouched, no
  remote tags. Local chain verified first: 7 linear commits
  `1fad93b` → `bd19855` → `cda3462` → `93185f5` →
  `f086a64` → `c5691e6` → `28c1b18` on top of `0a5d052`,
  no deletions, no binaries, all UTF-8, secret-pattern scan
  clean, messages preserved verbatim.
- Published chain, in order, each on the previous head
  (head re-checked live before every push; no force-push,
  no rewrite of remote history):
  - `1fad93b` (audit fixes) → `ef2eb12`
  - `bd19855` (milestone 2) → `419daab`
  - `cda3462` (rc.1) → `edf983c`
  - `93185f5` (rc.1 push record) → `26eced2`
  - `f086a64` (rc.2 hardening) → `de2214c`
  - `c5691e6` (rc.2 push record) → `23dc057`
  - `28c1b18` (rc.2 delivery record) → `248af16`
  Full remote SHAs are in the delivery report; short SHAs
  above are unambiguous here.
- Verification after each push (fetch + inspect, not the
  push receipt alone): parent chain is linear from
  `dd22172` to `248af16`, subjects match, and every file's
  content is byte-identical to the local commit. Trees
  1–4 are exactly equal to local trees. Trees 5–7 differ
  from local trees by ONE item only: `run.sh` mode.
- KNOWN DEVIATION — `run.sh` executable bit (disclosed, not
  hidden): local `run.sh` is mode 100755 with blob
  `411e15c3…`; the connector's file API writes updated
  files at mode 100644, so published `run.sh` has the
  identical blob but mode 100644. Cause: the API exposes
  no mode control, and a pre-push check that piped the
  range summary through `head` missed that `run.sh` is the
  one executable file in the range. Impact: NONE on
  Windows (checkouts ignore exec bits); on Linux/macOS
  run `bash run.sh` or `chmod +x run.sh` after cloning
  until a later commit restores the bit through a
  mode-aware push. Content is unaffected.
- Tags: local tags UNTOUCHED (`v1.0.0-rc.1` → `cda3462`,
  `v1.0.0-rc.2` → `f086a64`, never moved). The connector
  has no tag-creation tool (only tag reads), so
  `v1.0.0-rc.2` was NOT published from here. The correct
  published target is the rc.2-equivalent commit
  `de2214c` (content-verified above). The Windows
  commands to create and push the tag are in the delivery
  report; a release object was NOT created to mint the
  tag, because the user authorized a tag, not a release.
- Windows fast-forward (clean tree, from the user's
  `dd22172`): `git fetch origin` then
  `git merge --ff-only origin/feature/cyberllm-desktop-portable`.
  No patches, no rebase, no force-push on either side.
- Local branch note: this VM's branch keeps the local
  SHAs (content-identical modulo the `run.sh` mode bit);
  the published chain is canonical on GitHub. The next
  development session must start from the published tip
  before new work, or it will diverge again. Working
  tree still only the 2 evaluation files
  modified-unstaged, never committed.

## 2026-10-29 — Fix: detection-to-report persistence (audit follow-up)

- Audit finding: finished scans lived only in ScannerPage memory and
  Reports & History generates nothing, so findings vanished on
  navigation/restart. Demo scripted scans discarded findings behind
  a false "See the Scanner page" claim; failed scans left stale
  results exportable.
- Fix: `reports.save_scan_report` (JSON+HTML auto-save, Windows-safe
  names, no-overwrite suffix); `ScannerPage._scan_done` auto-saves
  every finished scan; `_scan_error` clears stale results;
  `DemoPage._scripted_done` auto-saves under the `scan-demo`
  prefix. No AI interpretation of scan findings was added: scan
  reports are deterministic by design, and no code path feeds scan
  findings to the model.
- Tests: new `security_lab/tests/test_scan_report_persistence.py`
  (7 tests, failed 7/7 before the fix). Suites at this commit:
  root 635 passed + 1 skipped, lab 93 passed + 1 skipped,
  0 failed. Real lab E2E: 14 findings reloaded with correct
  target. Full audit: `reports/SECURITY_LAB_DETECTION_AUDIT.md`.
- Evaluation files not committed (test-regenerated churn, preserved
  uncommitted per standing rule; pre-audit copy backed up outside
  the repo).

## 2026-10-30 — Publish reliability + website-backend fixes (11 fixes)

- Reliability pass (5): Settings from_dict per-field defaults +
  allowlist coercion; BackendManager readiness via trust_env=False
  session; diagnostics check_reports round-trips save_scan_report;
  Control Center log-view placeholder for externally-started
  backends; Scanner.run() closes its HTTP session in finally.
- Website-backend pass (6): lab-run detection attributed to the
  test's own time window (not 900s recency + first-30 cap);
  non-ModelUnavailable inference failures now 503 model_error
  with deterministic findings; ATTACT report_json redacted before
  serializing; bridge dedup key persisted atomically at incident
  creation; list_runs clamped to [1, 50]; rate-limit key uses
  trusted_client_ip (XFF only from TRUSTED_PROXY_IPS/CIDRS).
- Tests: +15 (8 lab-side, 7 website-side). Suites at this commit:
  root 642 passed + 1 skipped, lab 101 passed + 1 skipped,
  0 failed. Evaluation files not committed (test-regenerated
  churn, preserved uncommitted).
- Tag v1.0.0-rc.2 already on the remote at de2214c (published
  by the user from Windows); no tag action in this delivery.
