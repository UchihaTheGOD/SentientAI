# Full SentientAI + CyberLLMv1 Integration Audit

Date: 2026-10-30. Branch: `feature/cyberllm-desktop-portable`.
Local HEAD at audit start: `90c70fc` (= published `1a6f6dbf461b75a2ae7376c6aa1c4ca1db66549e`,
verified live; remote tip unchanged at audit end).
Working tree at audit start: ONLY `evaluation/latest.json` +
`evaluation/moderation_latest.json` modified (test-regenerated churn,
never committed). `security_lab/tests/test_backend_python.py` is
CLEAN (last touched `bd19855`) — the suspected local modification
does not exist. No commit, push, reset, clean, rebase or force-push
was performed in this audit, per instruction.

Windows news received with this mission (user-reported, not
independently re-verified here): the GUI executable built and
launched, and a local Security Lab scan completed with 14 findings,
32 requests and an automatically saved JSON report. Those numbers
match the VM lab E2E exactly (same lab-server target class), and
they confirm the 2026-10-29 persistence fix works on Windows:
findings no longer vanish when the Scanner page is left.

## 0. Short answer

There is no single broken pipe losing findings. There are **four
separate pipelines that share a name ("security lab") but almost no
data**, and one of them — the desktop scanner — was designed to
never send anything to the model. Findings "missing" from AI reports
are, in almost every case, findings that were never submitted to
any AI path, because no code path submits them. That is
architecture, not a dropped message — but it is also the single
largest expectation gap in the product, and it must be labelled as
such in the UI and docs rather than left for users to discover.

The two real defects found in this audit were both silent-loss bugs
in export/analysis paths, and both are fixed below with regression
tests: (1) lab evidence truncation was undisclosed; (2) case CSV
export dropped evidence and notes. No serialization, API, database
or rendering loss was found anywhere else: every other path was
traced field by field and preserves what it claims to preserve.

## 1. Data-flow diagram

```
DESKTOP APP (security_lab/, PySide6, user data dir)
====================
Scanner page ──HTTP probes──> AUTHORIZED TARGET (user-approved only)
  │  (ScanConfig.authorized must be True; localhost/private/metadata
  │   blocked unless explicit local-lab config; GET + one gated TRACE)
  ├─> in-memory table (filters are display-only)
  ├─> AUTO-SAVE scan-*.json + scan-*.html  ──> Reports & History page
  │      (lists every file in the reports dir; timeline = counts only)
  └─> manual "Create case" ──> cases.json ──> Case Management page
        (JSON export complete; CSV export NOW includes evidence+notes)
  ✗ NO arrow to any backend AI endpoint (grep-verified: the Scanner
    page makes zero backend client calls).

Model Testing page ──pasted/loaded log text──> POST /api/sentinel/analyze
  or /api/cyberllm/analyze (auth + CSRF + rate limit)
  ├─> rules (50%) + CyberLLMv1 model (50% when confident)
  ├─> needs_review on unavailable / unparseable / truncated /
  │   mismatch / unjustified-threat; SSRF deterministic override
  └─> displayed result only — single analyses are NEVER saved
        (batch evaluations CAN be exported; documented limitation).

Classroom Demo page ──CANNED scenario logs──> screen() + analyze()
  └─> AUTO-SAVE scan-demo-*.json/html, labelled SIMULATED.
        Demo "AI results" are analyses of canned text, not of scans.

Control Center ──> backend health/readiness/device/quant/GPU display
  (readiness is honest: not_loaded/not_initialized when down).
  Model loads LAZILY inside the backend on first analyze; the GUI
  has a client.load_model() method that NO page calls (gap G-3).

WEBSITE BACKEND (app/, SQLite app.db)
====================
Incoming HTTP to the website itself ──middleware──> SecurityEvent rows
  (http.{status} + suspicious_input.{xss,sqli,traversal} from query
   params + auth.login_failed; NOTHING else is collected.)
  ├─> Admin Security pages (events / reports / assessments)
  ├─> POST /api/admin/security/analyze/event|finding (background,
  │   via bridge) ──> incident ──> training candidate
  └─> website lab: POST /api/security/lab/run (admin-only)
        TestClient probes against the OWN app + synthetic cases
        (is_synthetic labelled; detection = the run's own time
        window, fixed 2026-10-29) ──> SecurityLabRun rows
        └─> POST /api/security/lab/analyze (log_text | lab_run_id |
              event_ids) ──> classify + fuse ──> incident ──>
              training candidate (collect_from_incident)

ATTACT (ATTACT/runner.py, website-only) ──probes──> target
  └─> AttactAssessment + AttactFinding rows ──> bridge ──> incident
        ──> training candidate. (Desktop scanner findings do NOT
        take this path: the website never imports security_lab.)

REVIEW QUEUE (the ONLY queue in the system)
====================
TrainingExample rows with status "candidate" ──> admin_training page
  ──human approve/reject──> CLI export-training exports APPROVED
  examples only. Scanner findings are NEVER candidates by design:
  a scanner observation is not a labelled training example, and
  auto-promoting one would corrupt the training set. Any proposal
  to "send scan findings to the review queue" must answer what
  label, what ground truth, and whose approval — it is a product
  decision, not a bug fix.
```

## 2. The nine questions, answered

1. **Why might a GUI finding not appear in an AI report?**
   Because AI reports do not consume scanner findings at all. The
   desktop scanner writes deterministic JSON/HTML reports; the
   website's "AI reports" (incidents, assessments, lab analyses)
   consume log text and website events only. There is no join
   between the two stores (desktop files vs website SQLite).
2. **Are scanner findings ever submitted to CyberLLM?** No.
   Grep-verified: the only desktop callers of `analyze`/`screen`
   are Model Testing (user-supplied text) and Demo (canned text).
3. **Do AI reports only process logs and ignore scanner findings?**
   Yes — by design. `analyze` takes log text (max 8000 chars,
   over-long input is REJECTED, not truncated); `lab_analyze`
   takes log text, a lab run id, or event ids.
4. **Are scanner findings stored in a format fit for AI analysis?**
   The JSON is complete (all 11 Finding fields, redacted at
   construction), so a future feature COULD serialize findings to
   text and analyze them. Nothing does so today. Format is not
   the blocker; the missing feature is.
5. **Does report generation filter severity/category/type?**
   No. Scan JSON = full `to_dict()`; scan HTML iterates all
   findings; Reports page lists every file in the reports dir.
   Scanner-page table filters are display-only and never affect
   exports (re-verified). The one filter that DID lose data was
   the case CSV export (fixed below).
6. **Is anything lost in serialization / API / DB / rendering?**
   No, except the two fixed defects. Evidence redaction is
   intentional (secret-shaped strings masked at collection in
   both stacks; sensitive-file findings never store bodies;
   cookie values never stored). Truncation in `lab_analyze`
   evidence assembly was the silent loss (fixed below).
7. **Do frontend and backend use different schemas?** Yes, four
   of them, none shared — and that is correct for their jobs:
   desktop `Finding` (name/category/severity/confidence/status/
   explanation/evidence/url/impact/remediation/reference);
   classifier output (classification/model_classification/
   confidence/summary/indicators/reasoning/limitations/
   recommended_actions/deterministic_findings/decision_source);
   incident (fused_score/fused_verdict/rules/log_text); ATTACT
   finding (assessment rows). The failure mode this creates is
   conceptual, not technical: a user cannot paste a desktop
   finding into a field that expects log text and get a
   meaningful result without a translation step that does not
   exist.
8. **Is the AI Review queue meant to receive scanner findings?**
   No. It receives training candidates derived from incidents
   (website events, ATTACT findings via bridge, lab analyses).
   Desktop scanner findings have no incident, no label, and no
   path there. This matches the stated architecture and the
   training-data integrity rule; changing it needs a labelling
   design, not a pipe.
9. **Can a successful scan produce findings that never reach the
   AI pipeline?** Yes — every successful scan does, by design.
   "Never reach the AI pipeline" is the current normal, not an
   error state. The fix for the expectation gap is a labelled
   feature or labelled UI copy, not a silent wiring.

## 3. External attacks and logs: what is actually observed

Supported data sources (complete list, verified in code):

| Source | Observed? | How |
|---|---|---|
| Requests TO the SentientAI website | Yes | Middleware: status events + suspicious query params + login failures |
| Responses to the desktop scanner's own probes | Yes | 14 checks against the authorized target only |
| Responses to website lab TestClient probes | Yes | Own app only, admin-only, synthetic labelled |
| Responses to ATTACT probes | Yes | Website-only tool, own assessments |
| Pasted / file-loaded log text (desktop + website) | Yes | Manual user action; 8000-char cap, over-long rejected |
| Canned demo scenarios | Yes | Clearly labelled SIMULATED |
| Firewall / proxy / system / OS / container logs | NO | No collector, no importer, no parser exists |
| Log-file upload or ingestion | NO | No UploadFile endpoint anywhere in app/ |
| Traffic to third-party sites, or to a target from other clients | NO | The scanner sees only its own probes' responses |
| Outgoing requests from the website to other services | NO | Not logged as security events |

Classification the user asked for:

- **Confirmed detection:** an observation the check itself
  verified (e.g. a header is absent, a path returns 200, a
  marker reflects). Status `verified` means the OBSERVATION is
  confirmed — it never means exploitation was confirmed. No
  finding in either stack claims a confirmed vulnerability from
  a missing header, error string or version banner alone.
- **Suspicious indicators:** status `suspected` (reflected
  marker, error signature, version banner, SSRF sink) and all
  `needs_review` classifier outputs.
- **Unobserved attacks:** any attack that did not hit the
  website, was not probed for by the scanner, and was not
  pasted in. This is the overwhelmingly common case for
  "missing external attacks" and is a visibility limit, not a
  detection failure. A passive log pipeline cannot discover
  events absent from its input, and this product has no
  passive collector at all.
- **Unsupported data sources:** firewall/proxy/system logs,
  SIEM feeds, uploaded log files, third-party traffic. None
  are ingested; none are claimed in the docs audited.

Missing-data causes, checked one by one: no log collector
(CONFIRMED — the cause for most "missing logs"); incorrect log
paths / permissions / formats / parsing errors / timezone
issues / sampling / truncation — NOT APPLICABLE (no collector
to misconfigure); filters excluding events — only the
documented ones (middleware logs suspicious query params only,
not bodies; lab detection uses the run's own time window);
request sampling — none (middleware logs every request's
status event); API integration missing — yes, in the sense
that no external log API exists; target misconfiguration —
possible per-scan (allowlist refusal is loud, not silent);
network visibility — the fundamental limit (scanner sees its
own probes only); frontend display limits — timeline shows
counts only by design, details live in the report files.

## 4. Nine Security Lab pages: verdicts

1. **Website & Model Control Center** — WORKS. Real backend
   health/readiness/device/quantization/GPU (via `gpu_info`),
   start/stop/restart/refresh, settings save, adapter-SHA verify,
   diagnostics launch, log tail with the externally-started
   placeholder. Gap G-3: no Load-model button (client method
   exists, unused); loading is lazy on first analysis.
2. **Authorized Website Security Scanner** — WORKS. 14 checks,
   allowlist + refusal, rate limit, deadline, stop, progress via
   signal, stale-worker guard, auto-save JSON+HTML, stale-result
   clearing on error, manual case creation, exports. Windows
   result (14 findings / 32 requests / auto-saved JSON)
   confirms it end to end on the exe.
3. **Model Testing & Evaluation** — WORKS, with limitation L-2:
   single/batch analyses, baseline compare, exports; single
   analyses are displayed but never saved (batch exports work).
4. **User Management** — WORKS (admin session, list/search with
   debounce, role/active/suspend/create/reset, backend-enforced
   guards: no self-change, no last-admin removal; 401 disables
   actions). Requires a live admin backend; not testable with
   the backend down, by design.
5. **Reports & History** — WORKS (after the 2026-10-29 fix).
   Lists every file in the reports dir + last 200 timeline
   entries; open-in-viewer works. Timeline is count-only by
   design — detail lives in the report files, which is where a
   user looking for findings should look.
6. **Case Management** — WORKS, with fixed defect F-2. Manual
   cases from findings, statuses, notes, JSON export complete;
   CSV export previously dropped evidence+notes (fixed).
7. **Classroom Demo** — WORKS, honestly labelled. Canned
   scenarios analyzed via screen()+analyze(); results labelled
   SIMULATED and auto-saved with the scan-demo prefix. Demo
   output must never be quoted as a real assessment.
8. **Diagnostics** — WORKS. Nine checks incl. the auto-save
   round-trip (added 2026-10-29); writes go to a tempdir, never
   the data dir; model-inference check skips cleanly without
   weights.
9. **Settings** — WORKS. Per-field safe defaults + allowlist
   coercion (fixed 2026-10-29), bounds validation, save/reset
   reload. Hand-edited settings.json can no longer poison a
   later scan with string values.

Layout / clipping / scaling / resizing in the Windows exe:
NOT TESTED here (no Windows host, no exe in this VM). Windows
procedure is in §8. No layout defect is claimed or denied.

## 5. CyberLLM inference verification

Identity (verified in source on both stacks, values identical):
base `Qwen/Qwen3-1.7B` @ `70d244cc86ccca08cf5af4e1e306ecf908b1ad5e`,
adapter Pilot v8 (data-v3.2), SHA-256
`d624ed793a45a64cb541577441c87c7d2feb83c37a84da057d1c15e58e45a5b1`
— loader default, desktop config constant, and readiness
default all agree. The loader refuses on adapter SHA mismatch
and refuses a half-configured explicit model root rather than
silently falling back. Device: auto/cpu/cuda env; CUDA uses
float16 (correct for Turing, which has no BF16); 8-bit via
BitsAndBytes flag. Inference: greedy, semaphore 2, frozen
templates verbatim, budgets 320 (log/http/url) / 512
(vulnerability), `enable_thinking=False`, truncation flagged
when output hits the budget. Failure honesty: model-down gives
503 `model_error` WITH deterministic findings (fixed
2026-10-29); unparseable/truncated/mismatch outputs downgrade
to `needs_review`, never to a clean verdict.

NOT VERIFIED here (stated, not claimed): real GPU inference,
VRAM, latency, threat recall / false positives / abstention on
the user's hardware. This VM has no GPU, no torch in the
backend venv, and no weights. Prior real-inference evidence is
from 2026-10-24 CPU runs (Pilot v8: load 16.3 s, peak RSS
4.53 GB, ~1.5–1.9 tok/s, valid JSON on all probe cases) — that
is CPU evidence, not GPU evidence, and it predates this
branch's migration. Windows procedure is in §8; do not treat
this audit as inference verification.

## 6. Code changes made in this audit (published after user approval on 2026-10-31)

F-1. `app/api/security_lab_api.py::lab_analyze` — evidence
assembly for `lab_run_id` / `event_ids` silently capped each
event at 1200 chars and the total at 7000 chars. The response
now carries `input_truncated` (bool) and `input_chars` (chars
actually analyzed, synthetic prefix included). The `log_text`
path is unaffected (over-8000 input is rejected, not cut).
Test: `tests/test_security_lab_phase.py::
test_lab_analyze_reports_input_truncation` (long evidence ->
True + chars <= 7000; short evidence -> False).

F-2. `security_lab/cases.py::CaseStore.export_csv` — the CSV
exported 8 columns and dropped `evidence` and `notes`, while
the JSON export was complete. The CSV now has `evidence` and
`notes` (notes as JSON) columns. Evidence is already redacted
at case creation; notes are analyst text (UI warns against
secrets). Test: `security_lab/tests/test_cases_timeline.py::
test_case_exports` extended (asserts both columns and a note
round-trip).

No other code was changed. In particular, no scanner→AI wiring
was added: that is a product decision (see §7), and wiring it
silently would violate the honesty contract (model text
presented as detections) and the training-data rule.

## 7. Cleanup: classification and verdict

Method: every module's importers counted (including aliased
imports — `tags as tag_service` in `app/api/blog.py` initially
looked unused and is not), every static asset checked against
templates, every doc/asset checked for references, every
dependency checked against its real import form (uvicorn via
`run.py`; httpx test-only per its own comment; python-multipart
via FastAPI internals; argon2 via passlib). One early grep
pattern missed relative imports and was corrected before any
conclusion was drawn; no classification below rests on it.

Class A (definitely unused, safe to remove): NONE found among
tracked files. Every `app/services/*` module has ≥1 real
importer; every `security_lab/*` module has ≥3; all 13 static
JS/CSS files are referenced exactly once in templates; all 10
`requirements.txt` + 2 `requirements-dev.txt` entries are live.

Class B (duplicate / superseded, verified replacement):
- `sentientai-cyberllm-windows (1).patch` (tracked, 86,404 B).
  Superseded as a delivery method by real commits (2026-10-29).
  NOT deleted in this audit: it is still referenced by
  `CYBERLLM_WINDOWS_SETUP.md` and
  `reports/full_validation_report.md`. Deletion requires
  updating both references. PROPOSED for user decision.
- Duplicate `redact()` implementations (`app/services/
  security_events.py` vs `security_lab/scanner/findings.py`).
  Intentional: two packages with no shared dependency; unifying
  them would couple the desktop app to the website. RETAIN.

Class C (historical documentation, retain):
- Root docs (13): README, CHANGELOG, DEVELOPMENT_LOG,
  CYBERLLM_PORTABLE_SETUP, CYBERLLM_WINDOWS_SETUP,
  WINDOWS_TEST_CHECKLIST, CYBERLLM_INTEGRATION,
  CYBERLLM_INTEGRATION_REPORT, CHECKPOINT_DB_SCHEMA_FIX,
  DOCUMENTATION, IMPLEMENTATION_REPORT, PROGRESS,
  VERIFICATION_REPORT. All live or historical record; none
  deleted. `reports/*.md` (13, incl. this report's predecessors)
  likewise retained.
- `Documentation/` (78 files recursive) incl.
  `SENTIENTAI_COMPLETE_TECHNICAL_GUIDE.md`, which references
  `screenshots/` (8) and `diagrams/` (6) — assets retained.
- `TESTv1/` (16 tracked: 10 docs + 6 training_factory files).
  Zero references outside TESTv1, but user-owned training
  research tooling (phase2 PASS record in tracked
  `progress.json` points into it). RETAIN pending user say-so.
- `datasets/` (8 tracked CSIC files, ~86 MB). Training
  research input. RETAIN.
- `progress.json` (tracked phase tracker). RETAIN, untouched.

Class D (test coverage that must remain): all of it. No test
targets a removed module (only stale `__pycache__` bytecode
mentions old test names). `evaluation/latest.json` +
`evaluation/moderation_latest.json` are test-regenerated churn
and are NOT deleted (explicit user instruction); fresh backup
at `~/workspace/eval-backup-20261030/` (sha 9f3006aa… /
ecc9079a…).

Class E (generated / ignored artifacts): `__pycache__/`,
`.pytest_cache/`, `app.db` (gitignored, never committed),
`dist/` / `build/` (do not exist in this copy). No action
needed; nothing deleted.

Class F (unknown, needs investigation): NONE remaining after
this pass — every candidate examined resolved to A–E above.

Files removed in this audit: NONE. That is the safe-cleanup
result, not an omission: the 2026-10-27 migration already
removed the obsolete Sentinel code, and this pass found no
further tracked file whose lack of use is proven. Deleting
docs, tests, research or assets on age alone would have
destroyed history the user explicitly told us to preserve.

## 8. Remaining limitations and proposals (need user approval)

L-1. No external log collection (firewall/proxy/system/SIEM/
upload). PROPOSAL: a log-file import feature (explicit file
picker, format allowlist, parser errors surfaced, imported
events labelled by source) — new feature, needs design approval.
L-2. Single Model Testing analyses are never saved. PROPOSAL:
an "Export result JSON" button on the single-analysis pane
(writes the displayed result; no new persistence).
G-3. No Load-model button in Control Center (lazy load works;
`client.load_model()` exists but is unwired; load endpoint is
admin-only, so the button needs the admin-session pattern from
the Users page). PROPOSAL: add it.
G-4. Website lab detection still attributes by time window;
other traffic inside the same seconds-long window could be
misattributed. A correlation-id fix needs a middleware change
(it assigns its own per-request id and reads no client
header). PROPOSAL only.
G-5. Optional AI explanation of scan findings: serialize a
scan's findings to text, run them through `analyze`, and
display the result in a separate pane explicitly labelled
"AI interpretation — not a detection". This is the honest
form of "scanner findings in AI reports". PROPOSAL only —
it must never merge model text into the deterministic finding
list, and it must never feed the review queue without a
labelling design.
L-6. Batch evaluation and single inference have no cancel;
closing mid-run does not stop the in-flight request (bounded
by API timeouts). Documented since rc.2, unchanged.
L-7. Windows exe layout/scaling and Windows GPU inference are
still unverified by this audit (no Windows host here).

## 9. End-to-end verification checklist (Windows)

- [ ] Fetch + fast-forward to the published tip when the fixes
  below are published (do NOT publish without user approval):
  `git fetch origin` then
  `git merge --ff-only origin/feature/cyberllm-desktop-portable`
- [ ] Start backend: `.\run.bat start`; `GET /api/health` ok.
- [ ] Readiness before load: `ready=false`,
  `state=not_initialized`, device cpu, adapter SHA =
  d624ed79…5a5b1.
- [ ] Set env: `CYBERLLM_BASE_DIR=D:\CyberLLM\models\Qwen3-1.7B`,
  `CYBERLLM_ADAPTER_DIR=D:\CyberLLM\models\cyberllm-v8`,
  `CYBERLLM_ADAPTER_SHA256=d624ed79…5a5b1`,
  `CYBERLLM_DEVICE=auto`; restart backend.
- [ ] Load model (website admin readiness/load, or first
  analysis) — record load time, `nvidia-smi` VRAM before/after,
  device reported by readiness (expect cuda on the 1660 SUPER).
- [ ] Real inference battery (paste each into Model Testing):
  benign sudo log -> expect likely_benign; single SSH failure
  -> needs_review; web-scan log -> likely_threat; SSRF
  `GET /fetch?u=http://169.254.169.254/latest/meta-data/`
  -> likely_threat (deterministic override); CVE-2017-0142
  text -> needs_review or likely_threat with valid JSON.
  Record latency, output_tokens, truncated flag, parse_ok for
  each. Any unparseable case: send raw output + truncated +
  output_tokens.
- [ ] Scanner: authorized local-lab target scan -> findings
  table, auto-saved `scan-*.json` + `.html` in the reports dir,
  same findings after navigating away and back, and after
  restart. Refused scan (private target without local-lab
  config) -> loud refusal, no stale results.
- [ ] Reports & History: the new scan files listed; open one.
- [ ] Cases: create a case from a finding; export CSV; confirm
  the evidence and notes columns are present (F-2).
- [ ] Website lab analyze with a long-evidence run: confirm the
  response carries `input_truncated` (F-1).
- [ ] Exe layout: resize the window (incl. 1024x768), switch
  Windows scaling 100%/125%/150%, visit all nine pages, note
  any clipping or cut-off controls.
- [ ] Users page with an admin session; Diagnostics full run.

## 10. Test results

Before (committed state, 2026-10-30): website 642 passed +
1 skipped; lab 101 passed + 1 skipped; 0 failed.
After (this audit's working tree): website **643 passed + 1
skipped** (+1 new truncation test); lab **101 passed + 1
skipped** (case-export test extended, count unchanged);
0 failed. Targeted runs before the full suites: new truncation
test failed once on a test bug (detached SQLAlchemy instance
after session close — fixed in the test, not the code), then
passed; case tests 5/5. `git diff --check` clean. No test was
weakened and no safety check disabled.

Working tree at audit end (committed and published on
feature/cyberllm-desktop-portable after user approval):
- M `app/api/security_lab_api.py` (F-1)
- M `security_lab/cases.py` (F-2)
- M `tests/test_security_lab_phase.py` (F-1 test)
- M `security_lab/tests/test_cases_timeline.py` (F-2 test)
- M `evaluation/latest.json`, `evaluation/moderation_latest.json`
  (pre-existing test-regenerated churn, excluded from any commit)
