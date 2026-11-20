# SentientAI / CyberLLMv1 Security Lab — detection-to-report audit

Date: 2026-10-29. Base: branch `feature/cyberllm-desktop-portable`,
local tip `4496eba`, VERSION `1.0.0-rc.2`. Environment for this audit:
Linux VM (no GPU, no model weights, no torch). Nothing here was
committed or pushed; the changes below are uncommitted working-tree
changes, pending the user's approval to commit/publish.

## 1. Root-cause report

### 1.1 Exact cause

Scan findings never reached any durable report because **a finished
scan was stored only in ScannerPage memory** (`self._result`) and
nothing wrote it to disk. The only exits from memory were manual:
pressing Export (file dialog) or creating cases one finding at a
time. The Reports & History page generates nothing — it lists files
already in the reports directory plus one-line timeline events
(counts only, no finding detail). So after a scan, opening Reports &
History showed no new report, and restarting the app erased the
results entirely — including the table. That is the stage where the
findings disappeared: scan completion → persistence, which did not
exist.

Two secondary defects of the same class were found in code and fixed
in the same change set:

- **Stale result after a failed scan.** `ScannerPage._scan_error`
  left the previous scan in `self._result`, so Export after a refused
  or failed scan published the *previous* scan's findings under a new
  scan's context (wrong scan association).
- **Demo scripted scan discarded its findings.** `DemoPage`'s
  finished handler wrote only counts into a status label and claimed
  "See the Scanner page for detail" — but the Scanner page never
  received the result, so those findings existed nowhere.

### 1.2 What "AI-generated report" actually is in this codebase

There is **no code path that feeds scanner findings to the model**,
and no AI interpretation of scan findings exists anywhere in the
desktop GUI (verified by grep: the scanner and report pages make
zero backend client calls; the only `analyze`/`screen` calls are the
Demo page's simulated scenarios and the Model Testing page's pasted
inputs). Scan reports (`security_lab/reports.py`) are deterministic
by design: they render the scanner's own findings, evidence,
summary, errors, timeline, and limitations. Model analysis is a
separate tool for pasted logs/URLs, and its single-analysis result
is itself never saved to a file (on-screen only).

Consequence, stated plainly: if the expectation was "the report
contains AI verdicts on my scan findings", that feature does not
exist and this audit does not invent it — presenting model text as
detections would violate the project's honesty contract. The fix
below makes the real thing work: scanner findings, with evidence
and correct scan association, durably saved and displayed. An
optional future AI-summary section for scan reports (clearly
labelled as interpretation, never as findings) would be a new
feature needing separate approval, not a bug fix.

### 1.3 Data flow, traced file by file

GUI action → scan configuration → scan worker → engine → response
parsing → finding normalization → (no AI step for scans) → result
persistence → case/history storage → report aggregation → report
generation → GUI display:

| Stage | File / function | Input → output | Sync/async | Failure handling |
|---|---|---|---|---|
| GUI action, config | `gui/page_scanner.py::ScannerPage.start_scan` | Target + allowlist + categories + settings → `ScanConfig(authorized=True)` | GUI thread | Refuses to start without target, authorization checkbox, or a selected category (status text only) |
| Worker | `gui/workers.py::ScanWorker.run` | `make_scanner()` → `Scanner.run()` | QThread; `finished`/`error` signals to GUI thread | Exception → `error` signal with message |
| Engine | `scanner/engine.py::Scanner.run` | Base fetch, then each enabled check | Worker thread | Per-check `ScanRefused`/network/generic exceptions are caught, recorded in `result.errors`, scan continues. A refused/failed *base* fetch returns an empty result with errors (see §1.4) |
| Response parsing, checks | `scanner/checks.py` (14 checks) | Probe responses → `Finding` list | Worker thread | A check raising `ValueError` (bad severity/status) is caught by the engine as a check error; that check's findings are lost, others survive |
| Normalization | `scanner/findings.py::Finding.__post_init__` | Raw fields → validated fields, evidence redacted (secret patterns, 2000 chars), URL userinfo stripped + sensitive query values masked | Synchronous | Invalid severity/confidence/status raises; see above. Redaction masks secret-shaped strings only; sensitive-file evidence is status/length/type, body never stored |
| AI/model analysis | — (none for scans) | — | — | Model Testing (`gui/page_model.py`) is a separate pasted-input flow via `client.analyze`; never fed scan findings |
| Result persistence | **MISSING before this fix** — `page_scanner._result` only | — | — | App restart, or navigating without exporting, lost everything |
| Case storage | `cases.py::CaseStore.create_from_finding` | One selected `Finding` → one `Case` in `cases.json` | Synchronous on button press | Manual, one finding at a time; no scan association beyond title/URL/evidence |
| History storage | `timeline.py::Timeline.append` via `context.log_event` | One-line event strings → `timeline.jsonl` | Synchronous; `log_event` swallows exceptions | Timeline carries counts only ("target: N findings"), never finding detail |
| Report aggregation | `gui/page_misc.py::ReportsPage.refresh` | Files in reports dir + timeline entries → list + text view | `showEvent` + Refresh button | Lists whatever files exist; generates nothing |
| Report generation | `reports.py::export_scan_*` | `ScanResult` → HTML/JSON/CSV/PDF files | Synchronous on Export press | PDF raises a clear error without reportlab; JSON/CSV/HTML always available. Exporters use the full unfiltered result (table filters do not affect exports) |
| GUI display | `page_scanner._render_table` / `_show_detail` | Filtered findings → table + detail pane | GUI thread | Filters (severity/category/status/search) hide table rows only, never report content |

Field names are consistent across the whole path (`name`, `category`,
`severity`, `confidence`, `status`, `url`, `evidence`, `explanation`,
`impact`, `remediation`, `reference`); no renaming bug was found.
One pre-existing export limitation, not fixed here (minimal scope):
case CSV omits `evidence` and notes; case JSON is complete.

### 1.4 Reproduction steps (before the fix)

1. Start the GUI, open the Scanner page, run a scan against the
   local lab (or any authorized target). The table shows findings
   (lab: 14 findings, 32 requests).
2. Open Reports & History. No new report is listed — only files
   previously exported by hand, plus a timeline line giving the
   finding count and nothing else.
3. Restart the app. The Scanner table is empty; the findings are
   gone everywhere except a manual export, if one was made.
4. Variant (wrong association): run a successful scan, then run a
   refused scan (e.g. remove the host from the allowlist). Export
   still offered the first scan's findings.
5. Variant (demo): press "Run scripted lab scan" on the Demo page.
   The label claimed Scanner-page detail existed; it did not.

Additionally, a failed base fetch (target blocks the scanner, DNS
failure, allowlist mismatch) returns an empty `ScanResult` with the
failure in `result.errors`, which the GUI renders as "Scan finished:
0 finding(s) …; errors: K". The errors are surfaced (status suffix
and report errors section), so this is not silent — but the
all-zero summary cards read as a clean bill unless the errors are
read. After this fix, that empty result is auto-saved with its
errors intact, so the record is honest rather than clean-looking.

### 1.5 Fix applied and why it resolves the defect

Minimal, architecture-fitting changes (3 source files, 1 new test
file; no new pages, no API contract changes, no auth changes, no
second model loader, no SHA-verification bypass):

- `security_lab/reports.py`: new `save_scan_report(result,
  reports_dir, prefix="scan")`. Sanitizes host + start time for
  Windows filenames (colons stripped), creates the reports dir,
  appends a numeric suffix so two scans never overwrite each other,
  and writes JSON (complete record) + HTML (readable report) with
  the same stem. No model call is involved, so saving works when
  the backend/model is down — the deterministic fallback the
  mission requires.
- `security_lab/gui/page_scanner.py::_scan_done`: auto-saves every
  finished scan (including partial/stopped and 0-finding-with-errors
  results) and notes the path in the status line. A save failure is
  reported in the status line and never hides the table.
- `security_lab/gui/page_scanner.py::_scan_error`: clears
  `self._result` and re-renders for the current worker only (the
  stale-worker guard runs first), so a failed scan cannot export a
  previous scan's findings.
- `security_lab/gui/page_misc.py::DemoPage`: extracted
  `_scripted_done`, which auto-saves the scripted scan under the
  `scan-demo` prefix and states the saved path; the false "See the
  Scanner page for detail" claim is removed (the SIMULATED label
  is kept).

Why this resolves the definition of done: a controlled scan now
produces a known finding, the finding is written to a durable file
carrying the target, start/finish times, request count, and errors
(correct scan association), the Reports page lists it after refresh,
and the finding's evidence, severity, category, and status survive
byte-for-byte from engine to file (proven by the new tests and by a
real lab scan below).

### 1.6 What was NOT found (ruled out with evidence)

- No finding is dropped by the engine's check loop: per-check
  exceptions are caught and recorded, other checks continue.
- No finding is dropped by table filters in exports: exporters use
  the full result, not the filtered view (new test proves this).
- No finding is dropped by evidence redaction of ordinary scan
  evidence: redaction targets secret-shaped strings; sensitive-file
  findings never store bodies.
- No scan/session/case ID mismatch in reports: scan reports carry
  no case ID at all (they are keyed by target + timestamps); cases
  are a separate, manual, per-finding store.
- No demo/real mixing in saved reports: demo saves under a
  distinct `scan-demo` prefix and keeps the SIMULATED label; real
  scans save under `scan`.
- No worker-thread GUI corruption: progress/finished cross via Qt
  signals, stale workers are ignored (existing test + rc.2 fixes).

## 2. Integration audit matrix

Statuses: PASS = directly tested successfully. FAIL = reproducible
defect. PARTIAL = some stages work, end-to-end unverified. NOT
TESTED = no sufficient evidence. All rows verified against current
code; "tested" means exercised in this audit unless noted.

| GUI action / workflow | Source file / function | Backend / API | Data source | Expected result | Test | Actual status |
|---|---|---|---|---|---|---|
| Control Center: start/stop/restart, health, readiness, logs | `gui/page_control.py` | BackendManager via uvicorn subprocess; `GET /api/health`, `/api/cyberllm/readiness` | Backend state + readiness payload | Running state, device, load time, RSS, logs | Existing backend/control tests; rc.2 Linux boot test | PARTIAL — Linux-verified; Windows start, frozen-exe discovery, and real GPU reporting not tested here |
| Control Center: adapter SHA + artifact verification | `page_control.verify_artifacts` → `backend.check_artifacts` | None (local files + SHA) | Model dirs / manifest | Missing list or "Artifacts OK" + SHA status | Existing backend tests | PARTIAL — logic tested; the user's real adapter SHA check on Windows not run here |
| Scanner: run scan, table, filters, detail | `gui/page_scanner.py`, `scanner/engine.py`, `scanner/checks.py` | None (direct HTTP) | Live target responses | Findings with severity/status/evidence | Lab scan smoke + new persistence tests + real lab E2E (14 findings) | PASS — on lab target; behaviour on a real authorized target is target-dependent (see blockers) |
| Scanner: stop/cancel, stale-worker guard | `page_scanner.stop_scan/stop_all`, `gui/workers.py::ScanWorker` | None | Worker thread + stop event | Scan stops; late results ignored | Existing GUI smoke tests | PASS |
| Scanner: export HTML/JSON/CSV/PDF | `page_scanner._export` → `reports.export_scan_*` | None | In-memory result | File with all findings | Existing redaction tests + new tests | PASS |
| Scanner: auto-save on completion (NEW) | `page_scanner._scan_done` → `reports.save_scan_report` | None | Finished `ScanResult` | JSON+HTML in reports dir | New tests + real lab E2E | PASS |
| Scanner: failed/refused scan handling | `page_scanner._scan_error`, `engine.run` error paths | None | Errors list / refusal | Status states refusal; no stale export; empty result keeps errors | New tests | PASS (after fix; stale-export was FAIL before) |
| Model Testing: single analysis, parsed/raw display | `gui/page_model.py` → `client.analyze` → `model.shape_analysis` | `POST /api/cyberllm/analyze` (+ readiness) | Backend model or deterministic rules | Classification + raw + parsed panes, honest "not provided" gaps | Existing model/client tests with stubs | PARTIAL — display/parsing tested; real 1.7B inference NOT TESTED here (no weights/GPU) |
| Model Testing: batch evaluation, export, baseline | `page_model` → `evaluation.run_evaluation` | `client.analyze` per case | User JSONL/CSV + labels | Metrics or "not evaluated", exports, baseline diff | Existing evaluation tests | PARTIAL — same inference limitation; metrics logic tested |
| Model Testing: single-analysis persistence | (none exists) | — | In-memory `_shaped` only | No save/export for single analysis | Code inspection | PARTIAL (limitation, not a defect fix in this change set — see §5) |
| User Management: list, create, role, active, suspend, reset, audit | `gui/page_users.py` → `client` admin methods | `GET/PATCH/POST /api/admin/*` (admin-only, backend-enforced) | Backend user records | Safe fields only; guards enforced server-side | Existing GUI stub tests + client tests | PARTIAL — GUI + client mapping tested; live admin backend flow NOT TESTED here |
| Reports & History: list, open, timeline | `gui/page_misc.py::ReportsPage` | None | reports dir files + `timeline.jsonl` | Saved reports listed after refresh; timeline lines | New test (refresh lists auto-saved report) | PASS (after fix; before fix it listed only manual exports) |
| Case Management: create from finding, status, notes, export | `gui/page_misc.py::CasesPage`, `cases.py::CaseStore` | None | `cases.json` | Case persists, status/notes update, JSON complete (CSV omits evidence — noted §1.3) | Existing case/timeline tests | PASS |
| Classroom Demo: lab, scripted scan, simulation | `gui/page_misc.py::DemoPage` | Local lab only; `client.screen/analyze` for scenarios (degrades to "not measured") | Simulated scenarios | SIMULATED labels; measured-or-"not measured", never fabricated | Existing demo tests + new scripted-save test | PASS (after fix; scripted-scan loss was FAIL before) |
| Diagnostics: self-test incl. scanner safety + report generation | `gui/page_misc.py::DiagnosticsPage`, `diagnostics.py` | Backend readiness (reported, never assumed) | Settings, artifacts, backend, lab, tempdir exports | Per-check pass/fail/skip with fix hints | Existing diagnostics tests | PASS — except model inference, reported skipped-with-reason when backend not ready (honest, not a failure) |
| Settings: persistence, bounds, project/model paths | `gui/page_misc.py::SettingsPage`, `config.save_settings` | None (settings.json) | Settings object | Validated save; reset restores defaults | Existing GUI/config tests | PASS |
| Cross-cutting: scan → durable report → refresh | Scanner → `save_scan_report` → ReportsPage | None | reports dir | Finding + evidence + scan association survive and display | New contract tests + real lab E2E | PASS |
| Cross-cutting: AI interpretation of scan findings | (no such path exists) | — | — | Must not be presented as a feature | Code inspection (grep: zero client calls from scanner/report code) | NOT TESTED — feature does not exist; see §1.2 |
| Cross-cutting: backend readiness + GPU reporting | `backend.gpu_info`, readiness endpoint | Backend | nvidia-smi / torch | Device + VRAM + load time | rc.2 Linux boot test only | NOT TESTED here (no GPU/weights in VM) |
| Cross-cutting: real 1.7B inference | Backend loader + adapter SHA `d624ed79…5a5b1` | Backend | User's model dirs | Real verdicts with measured latency | Prior live CPU runs (2026-10-24, pilot v8/v3); GPU run never measured | NOT TESTED here |

No FAIL rows remain after this fix set. The two pre-fix FAILs
(stale export, demo scan loss) and the primary FAIL (no durable
scan report) are covered by the new tests.

## 3. Test report

Environment: Linux VM, Python 3.12, no GPU, no model weights, torch
absent by design from the backend venv. All commands run from the
repo root (`~/workspace/sentientai-main-audit` in this VM).

Baseline (before changes, 2026-10-29):

- `~/workspace/venvs/sentientai/bin/python -m pytest tests/` →
  **635 passed, 1 skipped** (54–55 s). Skip: pre-existing template
  skip, unchanged.
- `~/workspace/venvs/security-lab/bin/python -m pytest
  security_lab/tests/` → **86 passed, 1 skipped** (13 s). Skip:
  real-model smoke (needs weights + `CYBERLLM_REAL_MODEL=1`).

New regression/contract tests (written first, observed failing
7/7, then passing after the fix):

- `security_lab/tests/test_scan_report_persistence.py` — 7 tests:
  completed scan saved (JSON+HTML, evidence/severity/status),
  failed scan clears stale result, demo scripted scan saved,
  two scans never overwrite each other, saved report appears in
  ReportsPage after refresh, empty scan with errors saved honestly,
  table filters do not change the saved report. All 7 failed
  before the fix; all 7 pass after (one test initially failed on
  its own wrong assumption — it expected 1 listed file where the
  implementation correctly leaves 2, JSON+HTML — and was corrected
  to assert both).

Post-fix full runs:

- Lab suite: **93 passed, 1 skipped** (11 s) — baseline 86 + 7 new,
  0 failed. Targeted re-runs (new tests + redaction + GUI smoke):
  30 passed.
- Website suite: **635 passed, 1 skipped** (54 s), 0 failed —
  unchanged from baseline.
- Real end-to-end (throwaway script, not committed): engine scan
  against the local lab server → `save_scan_report` → reload:
  **14 findings, 32 requests, 0 errors**; all 14 reloaded with the
  correct target; `.env` finding present. Script removed after.
- Dependency checks: `pip check` in both venvs → "No broken
  requirements found."
- Lint/type checks: not run — the repo provides no lint/type
  configuration (no ruff/flake8/mypy/pyproject config found).
- Backend startup/readiness: verified on Linux in the rc.2 boot
  test (health ok, readiness honest `not_loaded` without weights);
  not re-run as a server in this audit because no code under
  `app/` changed.
- Real model inference: NOT TESTED here (no weights/GPU in VM).
  Existing tests mock the backend client; the deterministic
  report path (the fix) needs no model and is fully tested.

## 4. Change inventory

| File | Change | Reason | Regression test |
|---|---|---|---|
| `security_lab/reports.py` (+37) | New `save_scan_report()` + filename sanitization | Durable scan record; the missing persistence stage | `test_scan_report_persistence.py` (all 7) |
| `security_lab/gui/page_scanner.py` (+21/−~0) | `_scan_done` auto-saves; `_scan_error` clears stale `_result` + re-renders | Findings reach a report; failed scans can't export stale findings | Same file, esp. completed-scan, failed-scan-clears-stale, two-scans, filters tests |
| `security_lab/gui/page_misc.py` (+23/−~0) | `DemoPage._scripted_done` (extracted from inline lambda) auto-saves with `scan-demo` prefix; removes false Scanner-page claim | Demo scripted findings no longer vanish | Same file, demo-scripted test |
| `security_lab/tests/test_scan_report_persistence.py` (new) | 7 contract tests | Prove the defect, then the fix, at the real seam | Itself (failed 7/7 before, passes after) |
| `reports/SECURITY_LAB_DETECTION_AUDIT.md` (new, this file) | This audit | Required deliverable | — (documentation) |

No other files changed. `app/` untouched. Auth, SHA verification,
rate limits, allowlist gates, and safety checks untouched. No test
was weakened or deleted; one new test was corrected (see §3).

Evaluation files: `evaluation/latest.json` and
`evaluation/moderation_latest.json` remain modified-unstaged, as
before this audit. They were NOT edited by hand; the root-suite
runs regenerate them (documented behaviour — the tests call
`run_evaluation(..., output_dir="evaluation")`). A byte copy of
their pre-audit contents is preserved outside the repo at
`~/workspace/eval-backup-20261029/`; they were not committed,
restored, or deleted.

## 5. Remaining blockers

- **Commit/publish approval for this change set.** Per the mission
  instructions, nothing here was committed or pushed. The fix is
  uncommitted in this VM only. Publishing (e.g. via the GitHub
  connector as in the previous delivery, then a Windows
  fast-forward) needs the user's explicit approval.
- **Windows verification.** Everything Windows-specific is still
  unverified here: Windows test run, exe build + double-click,
  backend start from the Control Center on Windows, GPU
  reporting on the GTX 1660 SUPER, and a scan against a real
  authorized target (lab-target behaviour is proven; real-target
  behaviour depends on the target).
- **Real model inference.** No weights/GPU in this VM. The
  1.7B + v8 adapter path (readiness device, load time, GPU fit
  and latency, benign/SSRF battery) still needs the user's PC.
  The fix does not depend on it (scan reports are deterministic).
- **Tag `v1.0.0-rc.2`.** Still unpublished: the connector has no
  tag-creation tool. Correct published target remains the
  rc.2-equivalent commit `de2214ca92ceb91a2b93b1edb0a4d3ed2f0ad76b`
  (see the previous delivery report for the two Windows tag
  commands). No new version or tag is created by this audit.
- **Single-analysis persistence (limitation, not fixed).** Model
  Testing single analyses are on-screen only; there is no
  save/export for a single analysis. Batch evaluations can be
  exported. Changing this would add UI and is left as a
  documented limitation, not smuggled into this fix.
- **User's unparseable case.** Still awaiting the raw output,
  truncated flag, and token count from the user's Windows run;
  unrelated to this scan-report defect (that case concerns model
  output parsing, which preserves raw output by design).
- **Known, unrelated, pre-existing:** `run.sh` is mode 100644 in
  the published GitHub chain vs 100755 locally (connector file
  API limitation, documented in the previous delivery). No
  Windows impact; on Linux run `bash run.sh` or `chmod +x run.sh`.

## 7. Reliability audit, continued (2026-10-29, after the first fix)

State at the start of this pass: local branch
`feature/cyberllm-desktop-portable` at `9f66f24` (the
detection-to-report fix), remote branch at `6981be2` (the published
equivalent), working tree clean except the two test-regenerated
evaluation files. The user published tag `v1.0.0-rc.2` from Windows
during this pass: it now exists on the remote pointing at
`de2214ca92ceb91a2b93b1edb0a4d3ed2f0ad76b`, the verified
rc.2-equivalent commit. That item is closed; no tag action remains
for the agent.

Scope of this pass: every `security_lab` module was read (GUI pages,
scanner engine + all 14 checks, findings, reports, cases, timeline,
context, client, backend manager, config, diagnostics, evaluation,
lab server, workers, dialogs, theme, entry point), plus the website
CyberLLM integration surface (loader, inference, API routes, schema,
classifier essentials, auth login flow, security-lab API routes,
router registration). Unrelated website features (blog, community,
social, feed) do not touch the detection pipeline and were not
audited line by line; that boundary is stated, not hidden.

### 7.1 New confirmed defects and fixes (all uncommitted)

No fix below was published automatically; all await the user's
approval, per the mission instructions.

1. **Settings coercion left garbage values in place**
   (`security_lab/config.py::Settings.from_dict`). Numeric
   conversions were grouped in one try block, so one bad
   hand-edited value left the remaining fields as unconverted
   strings, which would fail later at scan time; a string
   allowlist would have been iterated character by character by
   the host check. Fix: each numeric field falls back to its safe
   default independently; a string allowlist is split on commas;
   a non-list allowlist resets to empty. Tests:
   `test_hand_edited_settings_coerced_to_safe_values`,
   `test_non_list_allowlist_resets_to_empty` in
   `test_config.py`.
2. **Backend readiness polling ignored the no-proxy lesson**
   (`security_lab/backend.py::BackendManager`). `wait_ready` and
   `readiness` used plain `requests.get`, honouring environment
   proxies, while `BackendClient` deliberately disables them
   because proxy env vars have broken localhost requests before.
   The same local backend was therefore reached two different
   ways. Fix: the manager now holds a `trust_env=False` session
   used by both methods. Tests: no-proxy session flag,
   `wait_ready` via a fake session, non-200 readiness mapping in
   `test_backend_hardening.py`.
3. **Self-test did not cover the new persistence path**
   (`security_lab/diagnostics.py::check_reports`). It exercised
   only the manual exporters, so the auto-save path the Scanner
   page now relies on was untested by diagnostics. Fix:
   `check_reports` additionally round-trips a report through
   `save_scan_report` and verifies the finding survives. Test:
   `test_check_reports_includes_autosave` in
   `test_diagnostics.py`.
4. **Empty backend-log view gave no explanation**
   (`security_lab/gui/page_control.py::refresh_logs`). For a
   backend started outside the GUI, the log view stayed blank
   with no hint (logs are only tailed for GUI-started backends;
   an external backend logs to its own console). Fix: a
   placeholder explains this when no lines were captured. Test:
   `test_control_logs_placeholder_when_empty` in
   `test_gui_smoke.py`.
5. **Scan HTTP sessions were never closed**
   (`security_lab/scanner/engine.py::Scanner.run`). Every scan
   created a `requests` Session whose pooled connections lingered
   after the run. Fix: `run()` now delegates to `_run_impl` and
   closes the session in a `finally` block. Safe because every
   caller creates a fresh Scanner per run (verified by grep:
   scanner page, demo page, diagnostics). Test:
   `test_scan_closes_session_after_run` in
   `test_engine_hardening.py`.

### 7.2 Verified correct (no change made)

- Model identity pinning: base `Qwen/Qwen3-1.7B` @
  `70d244cc…`, adapter SHA
  `d624ed79…5a5b1` — identical in `security_lab/config.py`,
  `app/services/cyberllm_loader.py` defaults, and the live
  readiness payload (see §7.3).
- Loader: project-root-derived paths (never cwd or a personal
  Windows path), MODEL_ROOT precedence, manifest fallback, SHA
  check before the torch check, explicit-root incompleteness as a
  hard error, device auto/cpu/cuda with a clear error for
  cuda-without-GPU, fp16 on CUDA / fp32 on CPU, 8-bit only on
  CUDA, `model.eval()`, load failure recorded as
  `state=failed` + reason with an emptied bundle (no fabricated
  verdict downstream). Readiness staying unlocked during load is
  a deliberate tradeoff (a locked readiness would block for the
  whole load), not a defect: only the ready flag gates verdicts,
  and it is set under the load lock.
- Inference: frozen prompt templates verbatim, budgets 320/512,
  truncation flagged (never hidden), semaphore of 2,
  `torch.no_grad()`, greedy decoding, `enable_thinking=False`
  with fallback, input tensors moved to the model device.
- API: readiness unauthenticated; model load admin-only; screen
  and analyze authenticated; analyze rate-limited, input
  validated (422), `max_new_tokens` bounded 16–512 by schema,
  model-unavailable → 503 with reason + deterministic findings,
  unparseable output → `needs_review` with raw preserved,
  evidence-mismatch / truncation / unjustified high-confidence
  threat → downgraded, never silently confident.
- Schema: fence stripping, first-`{` strict JSON parse (trailing
  prose fails honestly), class/confidence/summary required,
  unknown keys dropped.
- Classifier: unavailable/unparseable/truncated/mismatch →
  `needs_review`; SSRF/metadata findings never lost to a benign
  model verdict.
- Auth: login/register return HTTP 303, matching the desktop
  client's success check; website security-lab routes are all
  admin-only; all CyberLLM routers are registered in `app/main.py`.
- Scanner checks (all 14): probe-response indicators only, never
  confirmed vulnerabilities from a header/error/version alone;
  SSRF sink labelled suspected without a fetch test;
  open-redirect uses exact hostname comparison and never follows
  the redirect; sensitive-file bodies never stored (status/length
  only); cookie values never stored (names only); error-page
  probes store signatures, not error text; TRACE goes through the
  gated request path.
- Lab server: loopback-only, GET-only (other methods 405),
  escaped search reflection, clearly fake `.env`.
- Windows packaging: `build_windows.bat` (build venv in `%TEMP%`,
  GUI deps `--upgrade`, spec with `console=False`, `datas=[]` so
  no weights are bundled), `run.bat` (`.venv` first, quoted paths,
  `cd /d %~dp0`), spec name correct. Paths with spaces are
  handled (quoted batch paths, `Path` objects, list-form Popen).
  The exe build itself remains Windows-only and untested here.
- Deliberately not changed (re-examined, still correct to leave):
  `BackendManager.stop()` kill-wait edge (state is cleaned in
  `finally`; a timeout surfaces as an error, never as success);
  `ScanContext` rate limiting is best-effort under the
  sensitive-files parallel probes (the cap itself is atomic);
  users-page KeyError exposure if the backend ever broke its
  admin payload contract (same-repo API; client validates dict
  shape); diagnostics' artifact-mismatch branch is unreachable
  because a mismatch is already in the missing list (harmless).

### 7.3 Backend live check (this VM, no model)

Started with the backend venv's uvicorn (as `BackendManager`
does), then stopped it cleanly:

- `GET /api/health` → `{"status":"ok","service":"sentientai"}`.
- `GET /api/cyberllm/readiness` → `ready=false`,
  `state=not_loaded`, `reason=not_initialized`,
  `base_model=Qwen/Qwen3-1.7B`,
  `adapter_sha256=d624ed79…5a5b1` (expected value),
  `device=cpu`, `quantization=none`. Honest: no weights or torch
  in this VM, so no load was attempted and no verdict fabricated.
- Shutdown completed cleanly; `app.db` SHA-256 unchanged by the
  check (backup taken beforehand at
  `~/workspace/appdb-backup-20261029.db` and not needed).
- Real Qwen3-1.7B inference, GPU detection on the GTX 1660 SUPER,
  and CUDA device selection remain NOT TESTED here (no GPU,
  weights, or torch in this VM) and need the user's PC.

### 7.4 Updated test results

- Lab suite: **101 passed, 1 skipped** (was 93+1; +8 new tests),
  0 failed. The 1 skip is the real-model smoke test (needs
  weights + `CYBERLLM_REAL_MODEL=1`).
- Website suite: **635 passed, 1 skipped**, 0 failed (unchanged;
  the pre-existing template skip).
- Targeted runs for the new fixes: 44 passed across the five
  touched test files.
- Real lab end-to-end after the session-close change: 14
  findings, 32 requests, 0 errors; all 14 reloaded with the
  correct target.
- Dependency checks: `pip check` clean in both venvs. Lint/type:
  no configuration exists in the repo, so none was run.
- Evaluation files: regenerated by the suite runs as usual;
  pre-pass bytes are preserved at
  `~/workspace/eval-backup-20261029b/` (plus the earlier
  `~/workspace/eval-backup-20261029/`); never committed.

### 7.5 Updated matrix deltas

- Diagnostics: PASS (now covers the auto-save path too).
- Control Center: PARTIAL (log placeholder added; Windows start,
  frozen-exe discovery, and real GPU reporting still untested
  here).
- Scanner / Reports / Cases / Demo / Settings: PASS (unchanged,
  re-verified by the full suites).
- Model Testing / User Management / backend readiness / GPU:
  PARTIAL or NOT TESTED as before — display, parsing, and client
  mapping are tested, but live inference and live admin flows
  need the user's backend + GPU.
- No FAIL rows remain in the matrix. The reliability pass found
  no defect in the detection pipeline itself (scanner → findings
  → persistence → report → display); the five fixes above are
  robustness, coverage, and resource-hygiene issues around it.

### 7.6 Changed files in this pass (UNCOMMITTED)

`security_lab/config.py`, `security_lab/backend.py`,
`security_lab/diagnostics.py`, `security_lab/gui/page_control.py`,
`security_lab/scanner/engine.py`,
`security_lab/tests/test_config.py`,
`security_lab/tests/test_backend_hardening.py`,
`security_lab/tests/test_diagnostics.py`,
`security_lab/tests/test_engine_hardening.py`,
`security_lab/tests/test_gui_smoke.py`, and this report file.
Evaluation files remain modified-unstaged by test regeneration
and are excluded from any commit.

### 7.7 Remaining blockers (updated)

- Publishing this pass's fixes needs the user's approval (not
  done automatically). The previous fix is already published at
  remote `6981be2`; the new fixes sit uncommitted on local
  `9f66f24`.
- Tag `v1.0.0-rc.2`: DONE — now on the remote at `de2214c`,
  published by the user from Windows. No tag action remains.
- Still Windows-only and unverified: Windows test run, exe build
  + double-click, backend start from the Control Center on
  Windows, GPU reporting + fit/latency on the GTX 1660 SUPER,
  real 1.7B inference, a scan against a real authorized target,
  and the user's unparseable case (still awaiting raw output +
  truncated flag + token count).
- Single-analysis persistence on the Model Testing page remains
  a documented limitation (on-screen only; batch evaluations can
  be exported). Changing it would add UI and was not smuggled
  into this pass.

### 7.8 Website-backend defects (second pass, same night)

A deeper read of the website backend (lab runner, ATTACT runner,
bridge, lab API, rate limiter, analyze error paths) found six
defects OUTSIDE the detection pipeline. Each was re-verified in
source before fixing; none was taken on trust. All fixes are
uncommitted, like the §7.1 set.

1. **Lab detection attributed by recency, not causality**
   (`app/services/security_lab_runner.py::run_lab_test`). After a
   test's requests, detection scanned the 500 most recent
   `SecurityEvent` rows, kept those from the last 900 seconds,
   and tested only the first 30. Any other user's failed login
   or suspicious request within 15 minutes made an unrelated
   test report `detected` (false positive); more than 30 events
   in the window could hide the test's own events (false
   negative). The per-request correlation ids were generated but
   never sent, and the middleware assigns its own per-request id
   and reads no client header, so id-based attribution is not
   available without a middleware change. Fix: detection now
   uses the test's own window (events created at or after the
   run started) and tests ALL window events; stored event ids
   are the window's events; `meta.events_attribution` records
   the method. Residual limitation, documented in code: other
   traffic landing inside the same seconds-long window could
   still be attributed; the 15-minute cross-talk is gone.
   Test: a benign custom test with a suspicious event seeded 10
   minutes earlier now reports `not_detected`
   (`test_lab_detection_ignores_events_before_the_run`).
2. **Non-`ModelUnavailable` inference failures lost their
   findings** (`app/api/cyberllm.py::analyze`). Only
   `ModelUnavailable` was mapped to 503 with deterministic
   findings; any other `generate()` failure (OOM, tokenizer,
   runtime) fell through to the generic 500 handler, which
   hides exception text by design — and discarded the
   deterministic findings computed before the call. Fix: a
   generic handler after the `ModelUnavailable` branch returns
   the same 503 shape with error code `model_error`, the reason,
   and the deterministic findings. Test:
   `test_analyze_generation_failure_is_503_with_findings`.
3. **ATTACT report blob stored unredacted**
   (`app/services/attact_runner.py::run_and_persist`). Finding
   rows were stored with `redact()` applied, but
   `assessment.report_json` serialized the raw report dict, so
   the same error bodies, sensitive-file bodies, and cookie
   excerpts persisted raw in the assessment row. Fix: each
   finding's evidence is redacted in the report dict before
   serialization. Test:
   `tests/test_attact_report_redaction.py` (secret-shaped
   evidence is absent from the blob and present only as
   `[REDACTED]`).
4. **Bridge incident creation committed before linking**
   (`app/services/sentinel_bridge.py`, both submit functions).
   `create_incident()` commits internally; the dedup key was
   set only in the later link block, so a link failure left a
   committed incident with no key, and a retry could not dedup
   against it and duplicated it. Fix: `create_incident()` takes
   an optional `containment_meta` persisted atomically with
   creation; both bridge paths pass the dedup JSON at creation.
   The dedup check (`key in containment_meta`) then finds the
   incident on retry. Test: a commit that fails exactly on the
   link commit, followed by a retry that dedups to the same
   incident
   (`test_link_failure_keeps_dedup_key_and_retry_dedups`).
5. **`list_runs` negative limit bypassed the 50-row cap**
   (`app/api/security_lab_api.py::list_runs`). `min(limit, 50)`
   with `limit=-5` is `-5`, and SQLAlchemy renders `LIMIT -1`
   on SQLite as no limit, returning the whole table. Fix:
   clamp at entry to [1, 50] and use the clamped value
   throughout. Test: with 55 rows, `limit=-5` returns 1 row
   (floor) and `limit=500` returns 50 (cap). Note: an early
   version of this test wrongly expected 50 rows for `-5`;
   the clamp semantics (floor 1, cap 50) are the correct
   expectation and the test was corrected, not the code.
6. **Rate-limit key trusted `X-Forwarded-For` blindly**
   (`app/services/ratelimit.py::_client_key`). Any client could
   rotate buckets with a fresh header value and defeat the
   20-per-600s analyze cap (and the login cap). Fix: use the
   codebase's own trusted-proxy policy
   (`security_events.trusted_client_ip`): XFF is honoured only
   when the peer is in `TRUSTED_PROXY_IPS`/`CIDRS`; otherwise
   the peer address is the identifier. The app binds localhost
   with no proxy-headers flag, so the default is the peer.
   Tests: spoofed XFF ignored without a trusted proxy; honoured
   when the peer is trusted
   (`tests/test_ratelimit_client_key.py`).

Updated test results for this pass: website suite **642 passed,
1 skipped** (635 + 7 new), lab suite **101 passed, 1 skipped**
(unchanged), 0 failed. Targeted runs for the six fixes: 49
passed across the touched website test files. Changed files in
this pass (uncommitted, in addition to the §7.6 list):
`app/api/cyberllm.py`, `app/api/security_lab_api.py`,
`app/services/attact_runner.py`,
`app/services/incident_service.py`, `app/services/ratelimit.py`,
`app/services/security_lab_runner.py`,
`app/services/sentinel_bridge.py`, `tests/test_bridge.py`,
`tests/test_cyberllm_api.py`, `tests/test_security_lab_phase.py`,
plus new `tests/test_attact_report_redaction.py` and
`tests/test_ratelimit_client_key.py`. The combined uncommitted
set (reliability pass + website pass) awaits the user's
approval; remote branch is still `6981be2`.

## 6. Windows verification instructions

Do these AFTER the fix is published (on approval) and the Windows
branch is fast-forwarded; the fix is not on GitHub yet, so do not
expect it before then.

PowerShell (from `D:\AI TEST\SentientAI-portable`):

```powershell
git status
git fetch origin
git merge --ff-only origin/feature/cyberllm-desktop-portable
git log --oneline -5
.\.venv\Scripts\python.exe -m pytest security_lab/tests/test_scan_report_persistence.py -v
```

GUI steps (no admin rights needed beyond the app itself):

1. Launch the GUI: `.\.venv\Scripts\python.exe -m security_lab`.
2. Scanner page: start the local lab, confirm authorization, run a
   scan. Confirm the status line ends with "Report auto-saved
   to …" and the table shows findings.
3. Reports & History page (or the reports folder under
   `%APPDATA%\CyberLLMv1 Security Lab\reports`): confirm a new
   `scan-127.0.0.1-<timestamp>.json` and matching `.html` exist,
   open the HTML, and confirm the findings, evidence, and target
   match the scan. Press Refresh on the Reports page and confirm
   the files list without restarting.
4. Close and reopen the GUI. Open Reports & History again: the
   saved report must still be listed (this is the persistence the
   bug removed).
5. Stale-result check: run a good scan, then run a refused scan
   (remove the host from the allowlist, keep authorization
   checked). Confirm the status says refused/failed, the table
   clears, and Export says nothing is available — the previous
   scan's findings must NOT be exportable.
6. Demo check: Classroom Demo → start lab → "Run scripted lab
   scan". Confirm the label gives an auto-saved `scan-demo-…`
   path and that file exists in the reports folder.
7. Optional, still open from before: backend readiness (Control
   Center → Verify adapter SHA + artifacts, expect the v8 SHA
   `d624ed79…5a5b1`), then a real authorized-target scan, and
   the benign/SSRF browser battery. Report back: Windows test
   counts, readiness device + load time (or `not_loaded` reason
   verbatim), GPU/VRAM + measured peak/latency, and the scan
   report filenames + finding counts.
