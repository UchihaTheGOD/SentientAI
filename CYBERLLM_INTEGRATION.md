# CyberLLM integration into SentientAI (branch: cyberllm-integration)

No new website, dashboard, or frontend was built. CyberLLM is exposed
through SentientAI's existing FastAPI backend, following the existing
Sentinel integration's patterns (lazy loading, auth-gated analysis,
fail-open when torch is absent, human-review honesty rules).

## What changed (5 new files, 1 edited)

| File | What it does |
|---|---|
| `app/services/cyberllm_loader.py` | Lazy base + LoRA adapter loader (mirrors `sentinel_loader.py`). Verifies the adapter sha256 before loading; records load failures instead of crashing the app. Env: `CYBERLLM_BASE_DIR`, `CYBERLLM_BASE_MODEL`, `CYBERLLM_BASE_REVISION`, `CYBERLLM_ADAPTER_DIR`, `CYBERLLM_ADAPTER_SHA256`. |
| `app/services/cyberllm_inference.py` | Greedy generation with the frozen eval prompt templates, verbatim (pilot v8 is prompt-sensitive). Budgets: 320 tokens log/HTTP/URL, 512 vulnerability. Reports truncation. |
| `app/services/cyberllm_rules.py` | Deterministic rules that run before the model: cloud-metadata SSRF, private/loopback fetch targets, credential-file probes, repeated probing. Every firing cites its evidence. |
| `app/services/cyberllm_schema.py` | JSON extraction + schema validation. Unknown keys are dropped. There is deliberately NO MITRE ATT&CK field: exact-ID performance is 0.000–0.025 across all pilots, so IDs are never presented as confirmed findings. |
| `app/api/cyberllm.py` | `GET /api/cyberllm/readiness`, `POST /api/cyberllm/readiness/load` (admin), `POST /api/cyberllm/screen` (rules only), `POST /api/cyberllm/analyze` (authenticated, `validate_log_text` 8000-char cap). |
| `app/main.py` (edited) | Registers `cyberllm.router` next to `sentinel.router`. Two lines. |

`tests/test_cyberllm_api.py` covers auth, validation, the screen rules,
the SSRF override, truncated-output degradation, and the 503 path.

## Safety contract

- Unparseable/truncated output -> `needs_review`, confidence low, raw text
  preserved, no fabricated classification.
- Low-confidence output -> `needs_review`.
- A high-severity deterministic finding can override a benign model verdict
  to `likely_threat`, transparently (`model_classification` keeps the
  model's answer; the override and its evidence are returned).
- Nothing submitted in a log is ever executed.
- No MITRE IDs are returned, confirmed or otherwise.

## Checkpoint selection

- Leading candidate: pilot v8 (Qwen3-1.7B, data-v3.2, adapter sha256
  `d624ed79…5a5b1`). Load it by pointing the env vars at the base model
  and the v8 adapter (see below).
- Fallback: pilot v3 (Qwen3-0.6B, data-v2, adapter sha256 `384d296a…8967`),
  the overall reference. Use `CYBERLLM_BASE_MODEL=Qwen/Qwen3-0.6B`,
  `CYBERLLM_BASE_REVISION=c1899de…`, `CYBERLLM_ADAPTER_DIR=<v3 adapter>`,
  `CYBERLLM_ADAPTER_SHA256=384d296a4ad5afb7b1523a8f2f3b8e0c07ad7a1ac7faf1b27d36436084bd8967`.
- Checkpoints are never modified. The loader only reads them; a sha
  mismatch refuses the load.

## Run it

```bash
# 1. Python deps (SentientAI's own requirements + model stack)
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pip install --index-url https://download.pytorch.org/whl/cpu torch
.venv/bin/pip install transformers==5.16.1 peft==0.20.0 accelerate==1.14.0

# 2. Point at a base model + adapter (symlinks keep checkpoints untouched)
ln -s <path-to-Qwen3-1.7B> local_models/cyberllm/base-1.7b   # or set env vars
ln -s <path-to-v8-adapter> local_models/cyberllm/v8
CYBERLLM_BASE_DIR=local_models/cyberllm/base-1.7b \
CYBERLLM_ADAPTER_DIR=local_models/cyberllm/v8 \
  .venv/bin/python run.py   # serves http://127.0.0.1:8000

# 3. Load (admin) and check
curl http://127.0.0.1:8000/api/cyberllm/readiness
```

Then, logged in as any user, POST to `/api/cyberllm/analyze`:

```bash
curl -X POST http://127.0.0.1:8000/api/cyberllm/analyze \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: $TOKEN" \
  --cookie "session=$SESSION" \
  -d '{"log_text": "Oct 24 07:12:01 web-1 sudo: deploy : TTY=pts/0 ; COMMAND=/usr/bin/systemctl restart nginx"}'
```

(Use the browser while logged in, or the test client's login helper, for
the session + CSRF token — same mechanism as the existing Sentinel UI.)

## Resource requirements (measured)

See `CYBERLLM_INTEGRATION_REPORT.md` for the measured load/inference
numbers on the hardware used for verification. Local pilot v8 inference
needs ~3.4 GB for bf16 weights plus the torch runtime; pilot v3 needs
~1.2 GB. The API stays up and returns 503 with the real reason when the
model cannot load.

## What the existing website still needs

Website form: `GET /cyberllm` (login required, same auth + CSRF as
`/sentinel`) renders `app/templates/cyberllm.html`, a form that POSTs
to `/api/cyberllm/analyze` and renders `classification`, `confidence`,
`summary`, `indicators`, `reasoning`, `limitations`,
`recommended_actions`, deterministic findings, and the `needs_review`
banner. It adds no new API surface.

Windows local run (GTX 1660 / 6 GB VRAM, float16 on CUDA, 8-bit and
CPU fallbacks): see `CYBERLLM_WINDOWS_SETUP.md` — base + adapter
download commands, file sizes, checksums, launch commands, and the
six-case website test battery.
