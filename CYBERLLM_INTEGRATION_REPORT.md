# CyberLLM × SentientAI — integration report (branch: cyberllm-integration)

Date: 2026-10-24. No training runs, no paid compute, no checkpoint
overwrites, no EXP-CLLM-008, nothing published. All model artifacts stayed
private and read-only; the loader refuses to load on a sha256 mismatch.

## A. Existing application audit (verified, not assumed)

SentientAI (`github.com/UchihaTheGOD/SentientAI`) is a FastAPI 0.115.6 +
Jinja2 + SQLAlchemy 2.0 community publishing platform (posts, comments,
likes, follows, messages, notifications, search) with a private admin
panel. Auth: JWT sessions (python-jose HS256), Argon2id passwords, CSRF
double-submit middleware, in-process sliding-window rate limiting, audit
log. Config: `app/config.py` Settings from environment / `.env`
(`SECRET_KEY` required in production). Entry point: `run.py` → uvicorn
`app.main:app` on 127.0.0.1:8000; app factory `create_app()` in
`app/main.py`, lifespan runs `init_db()` + Sentinel background warm-load
(fail-open without torch). DB: SQLite file, model-driven migrations.

Frontend: server-rendered Jinja2 templates (`app/templates`) + static
CSS/JS. No React/SPA. The frontend talks to the backend through normal
form posts and `fetch` calls carrying the CSRF token, same mechanism the
new endpoint uses.

Existing AI integration (the seam this work reuses): the Sentinel stack —
`app/services/sentinel_loader.py` (dual-checkpoint CPU loader, ~1.9 GB
RSS), `sentinel_inference.py` (greedy, semaphore 2, 12 s budget),
`sentinel_fusion.py` (deterministic brute-force/port-scan rules + fusion),
`sentinel_moderation.py` (structured JSON contract + human-review gate),
router `app/api/sentinel.py` (`POST /api/sentinel/analyze`, auth-gated,
`validate_log_text` 8000-char cap, incident persistence). Per the repo's
own README, Sentinel checkpoints load but produce 0% valid JSON today, so
fusion falls back to rules and human review remains the gate. CyberLLM
plugs into the same shape with a much stronger model.

Routes added by this branch (registered in `app/main.py`, 2 lines):
`GET /api/cyberllm/readiness`, `POST /api/cyberllm/readiness/load`
(admin), `POST /api/cyberllm/screen`, `POST /api/cyberllm/analyze`,
plus the website form page `GET /cyberllm` (login required, same CSRF
pattern as `/sentinel`).

## B. Model assessment

Two checkpoints were loaded with REAL weights and REAL inference through
the integration's own loader/inference code (not recorded outputs):

| Checkpoint | Base (pinned revision) | Adapter sha256 | Load | Verdict |
|---|---|---|---|---|
| Pilot v8 (leading candidate) | Qwen/Qwen3-1.7B @ 70d244cc… | d624ed79…5a5b1 | 16.3 s, RSS 1.12 GB after load | **RUNNING — live inference verified** |
| Pilot v3 (overall reference, fallback) | Qwen/Qwen3-0.6B @ c1899de… | 384d296a…8967 | 13.0–19.6 s, RSS 0.80–1.12 GB after load | **RUNNING — live inference verified** |

Both adapters were hash-verified before loading (the loader refuses on
mismatch). Pilot v6 was not loaded live; it remains the log-analysis
specialist on the strength of its frozen-eval record, untouched.

Limitations found live:
- A real integration bug was caught and fixed during testing: omitting
  `enable_thinking=False` made Qwen3 emit a `<think>` trace that consumed
  the whole token budget, so every output was unparseable. The frozen eval
  harness passes `enable_thinking=False`; the integration now does too.
  After the fix, all live outputs parsed as valid JSON.
- CPU speed on this 2-core VM is slow (see E). This is a dev-demo speed,
  not interactive-production speed; a GPU would cut latencies to seconds.
- Peak RSS during generation reached 4.53 GB (v8) / 2.28 GB (v3). The
  machine running inference needs that much free RAM, not just the load
  figure. The API stays up and returns 503 with the real reason when the
  model cannot load.
- MITRE ATT&CK exact-ID performance (0.000–0.025 across all pilots) is
  unreliable. The API has NO MITRE field at all, so no ID can be presented
  as a confirmed finding. EXP-CLLM-008 remains deferred.

## C. Integration results (files changed, branch cyberllm-integration)

| File | Change |
|---|---|
| `app/services/cyberllm_loader.py` (new) | Lazy base + LoRA loader mirroring `sentinel_loader.py`: sha verification, torch-optional fail-open, status dataclass, RSS reporting. Env: `CYBERLLM_BASE_DIR`, `CYBERLLM_BASE_MODEL`, `CYBERLLM_BASE_REVISION`, `CYBERLLM_ADAPTER_DIR`, `CYBERLLM_ADAPTER_SHA256`, plus `CYBERLLM_DEVICE` (auto/cpu/cuda; CUDA loads float16 — Turing cards such as the GTX 1660 have no bfloat16 support) and `CYBERLLM_LOAD_IN_8BIT` (bitsandbytes fallback for tight VRAM; untested on Windows). |
| `app/services/cyberllm_inference.py` (new) | Greedy generation with the frozen eval templates verbatim (`enable_thinking=False`), budgets 320 (log/HTTP/URL) / 512 (vulnerability), truncation flag, semaphore 2. |
| `app/services/cyberllm_rules.py` (new) | Deterministic rules: cloud-metadata SSRF, private/loopback fetch targets, credential-file probes, repeated probing. Each firing cites its evidence. |
| `app/services/cyberllm_schema.py` (new) | JSON extraction + schema validation; unknown keys dropped; no MITRE field; failures degrade to needs_review with raw text preserved. |
| `app/api/cyberllm.py` (new) | Readiness, admin load, screen, analyze (auth-gated, `validate_log_text` cap). Unparseable → needs_review; low confidence → needs_review; high-severity deterministic finding escalates a benign/needs-review model verdict to likely_threat transparently (`model_classification` preserved). Model unavailable → 503 with reason + screen findings. Also serves the `GET /cyberllm` form page (login required, redirect to `/login` otherwise). |
| `app/templates/cyberllm.html` (new) | Analyze form reusing the existing base layout and CSRF double-submit pattern; renders classification, confidence, summary, indicators, reasoning, limitations, recommended actions, deterministic findings, and the `needs_review` banner. |
| `.env.example` (new) | Copy-to-`.env` template (`.env` itself is gitignored) with the CyberLLM Windows paths and the adapter sha256; `app/config.py` loads `.env` before any router import, so these reach the loader. |
| `app/main.py` (edited) | Registers `cyberllm.router` next to `sentinel.router`. |
| `tests/test_cyberllm_api.py` (new) | 12 tests: auth, validation, screen rules, SSRF override, truncation degradation, 503 path, escalation logic, readiness quantization field, form-page login redirect + render. |
| `scripts/cyberllm_live_test.py` (new) | Live battery runner (real weights, integration code path). |
| `CYBERLLM_INTEGRATION.md` (new) | Runbook: deps, model placement, start commands, curl example. |
| `CYBERLLM_WINDOWS_SETUP.md` (new) | Windows local run: GTX 1660 / 6 GB VRAM analysis, exact base + adapter downloads, sizes, checksums, launch commands, six-case website battery, v3 fallback. |

No existing file besides `app/main.py` was modified. No existing route,
template, or behaviour was changed; the only frontend addition is the
single `cyberllm.html` form page above, not a new app.
Evaluation JSON files touched by running the repo's own test suite were
restored (`git checkout`) so the branch contains only the above.

## D. Test results

Live = real weights through the integration code. Recorded = pilot v8
frozen-eval raw generations fed through the endpoint code. Mocked =
synthetic model output testing endpoint logic only (labelled as such).

| Test | Input category | Expected | Actual | Status | Mode |
|---|---|---|---|---|---|
| v8 battery: benign sudo log | benign log | likely_benign | likely_benign, medium conf, valid JSON, 216 tok | PASS | LIVE v8 |
| v8 battery: single SSH failure | review log | needs_review | needs_review, low conf, valid JSON, 237 tok | PASS | LIVE v8 |
| v8 battery: 3-line web scan | threat log | likely_threat | likely_threat, high conf, valid JSON, 287 tok (+ credential/repeated-probe findings) | PASS | LIVE v8 |
| v8 battery: SSRF metadata request | threat HTTP | likely_threat | likely_threat, high conf, valid JSON, 221 tok (+ metadata_endpoint finding) | PASS | LIVE v8 |
| v8 battery: CVE-2017-0142 description | vulnerability | valid JSON or safe degradation | needs_review, low conf, valid JSON, 455 tok, no truncation | PASS | LIVE v8 |
| v3 battery: same 5 cases | mixed | benign/review/threat handling | benign ✓, review ✓, scan → needs_review (safe; deterministic findings fired), SSRF → likely_threat, CVE → needs_review, all valid JSON | PASS | LIVE v3 |
| Live server: register → login → analyze | benign log, real uvicorn | 200 + likely_benign | 200, likely_benign, source=model, parse=True, wall 123.6 s (cold: load + generation) | PASS | LIVE v8 via HTTP |
| Live server: unauthenticated analyze | auth | 401/403, no verdict | 403 (CSRF middleware, before auth) without token | PASS | LIVE server |
| Endpoint: SSRF override | threat HTTP | deterministic_override to likely_threat, model verdict preserved | exactly that | PASS | RECORDED v8 |
| Endpoint: CVE truncation | vulnerability | needs_review, parse_ok False, raw preserved | exactly that | PASS | RECORDED v8 |
| Endpoint: benign / validation / 503 / escalation | mixed | correct codes + verdicts | all as specified | PASS | RECORDED + logic |
| Full repo suite | regression | no new failures | 7 failures, all pre-existing (proven identical on a pristine clone: missing gitignored `local_models/sentinel/` checkpoints + tokenizer) | PASS (no regressions) | — |
| Browser workflow (click-through in a real browser) | end-to-end UI | — | NOT RUN: no browser session for localhost in this environment | BLOCKED (stated, not claimed) | — |

Notes on honest discrepancies:
- Frozen v8 eval recorded the SSRF item as likely_benign (the known miss);
  the live CPU run classified the same text likely_threat. Greedy decoding
  on CPU bf16 vs GPU fp16 can flip close decisions; the deterministic
  layer flags it either way, so the endpoint verdict is likely_threat in
  both worlds.
- Frozen v8 eval truncated the CVE item at 512 tokens; the live CPU run
  produced valid JSON at 455 tokens. Same numerics caveat; the endpoint
  degrades safely in both worlds.
- v3 live called the web scan needs_review while v8 live called it
  likely_threat. needs_review routes to human review — safe, not a miss —
  and the endpoint now escalates needs_review + high-severity findings to
  likely_threat.

## E. Performance (measured on this 2-CPU VM, CPU inference)

| Measurement | Pilot v8 (1.7B) | Pilot v3 (0.6B) |
|---|---|---|
| Model load | 16.3 s | 13.0–19.6 s |
| RSS after load | 1.12 GB | 0.80–1.12 GB |
| Peak RSS during generation | 4.53 GB | 2.28 GB |
| Per-request latency (216–455 tok) | 116–241 s (~1.5–1.9 tok/s) | 48–98 s (~4.4 tok/s) |
| Live HTTP cold first request (load + benign analysis) | 123.6 s wall | — |
| Readiness / screen endpoints | < 0.1 s (no model needed) | same |

## F. Current usability (evidence-based)

- [x] Model loads and inference works independently — v8 AND v3, live.
- [x] Backend integration works — new endpoints live in SentientAI,
  tested via TestClient and via real uvicorn + real login.
- [x] Existing website integration works — `GET /cyberllm` serves a form
  in the existing layout that posts to `/api/cyberllm/analyze` with the
  existing CSRF mechanism; covered by page tests (login redirect +
  render). What is NOT yet verified is a human click-through in a real
  browser.
- [ ] Full end-to-end workflow verified — the API leg and the page leg
  are verified; the browser click-through leg is not (no browser
  session here).

## G. How to use it

```bash
cd <sentientai-checkout> && git checkout cyberllm-integration
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install --index-url https://download.pytorch.org/whl/cpu torch
.venv/bin/pip install transformers==5.16.1 peft==0.20.0 accelerate==1.14.0

# Point at the models (symlinks keep checkpoints untouched; or set the env vars)
CYBERLLM_BASE_DIR=<path-to-Qwen3-1.7B> \
CYBERLLM_ADAPTER_DIR=<path-to-v8-adapter> \
CYBERLLM_ADAPTER_SHA256=d624ed793a45a64cb541577441c87c7d2feb83c37a84da057d1c15e58e45a5b1 \
  .venv/bin/python run.py   # http://127.0.0.1:8000

# Check readiness, then load (admin) if needed:
curl http://127.0.0.1:8000/api/cyberllm/readiness
```

While logged into SentientAI in the browser, POST `{"log_text": "..."}`
to `/api/cyberllm/analyze` with the session cookie + `X-CSRF-Token`
header (exactly like the existing Sentinel analyze call). The response
carries `classification`, `confidence`, `needs_review`,
`decision_source`, `summary`, `indicators`, `reasoning`, `limitations`,
`recommended_actions`, and `deterministic_findings`. Treat
`needs_review: true` as "a human must look at this" — that is the safe
state, not an error.

For the lighter fallback (v3, ~2.3 GB peak instead of ~4.5 GB):
`CYBERLLM_BASE_MODEL=Qwen/Qwen3-0.6B`,
`CYBERLLM_BASE_REVISION=c1899de289a04d12100db370d81485cdf75e47ca`,
`CYBERLLM_ADAPTER_DIR=<v3-adapter>`,
`CYBERLLM_ADAPTER_SHA256=384d296a4ad5afb7b1523a8f2f3b8e0c07ad7a1ac7faf1b27d36436084bd8967`.

## H. Remaining work (only actual blockers/improvements)

1. Browser click-through verification: run the `/cyberllm` form
   workflow in a real browser (the page and its tests exist; a human
   click-through has not been run).
3. Speed: CPU inference is 1.5–4.4 tok/s here. For interactive use, run
   the same code on a GPU host (the code is device-agnostic: CUDA is
   picked up automatically when torch sees it) or accept ~2-minute
   analyses on CPU.
4. The 7 pre-existing test failures (missing gitignored Sentinel
   checkpoints/tokenizer in a fresh clone) are unrelated to this branch
   but will fail for anyone else cloning fresh; restoring
   `local_models/sentinel/` fixes them.
5. MITRE attribution stays out of scope until EXP-CLLM-008 (deferred by
   you) is explicitly authorized; the API will not present technique IDs
   until then.
