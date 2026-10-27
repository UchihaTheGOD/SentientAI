# CyberLLMv1 Integration Report

Branch: `feature/cyberllm-desktop-portable` (code commit `8a5aee9`).
Model: CyberLLMv1 = Qwen/Qwen3-1.7B base + pilot v8 LoRA adapter, loaded
through one shared service. No other AI model performs inference anywhere
in the application or the desktop GUI.

## 1. Model identity (pinned, verified by hash)

| Item | Value |
|---|---|
| Base model | `Qwen/Qwen3-1.7B` (Apache-2.0, ungated) |
| Base revision | `70d244cc86ccca08cf5af4e1e306ecf908b1ad5e` |
| Fine-tuning | CyberLLMv1 pilot v8 LoRA adapter (r16/a32, data-v3.2) |
| Expected adapter SHA-256 | `d624ed793a45a64cb541577441c87c7d2feb83c37a84da057d1c15e58e45a5b1` |
| Adapter files | `adapter_config.json` + `adapter_model.safetensors` (canonical names; the Kaggle bundle names them `adapter_17b_datav32_*` — `adapter_17b_datav2_*` is pilot v4 and `adapter_datav32_*` without `17b` is pilot v7, do not mix them up) |
| Base files | 2 shards, 3,441,185,608 + 622,329,984 bytes (total 4,063,479,808) |

The loader refuses to load on adapter SHA mismatch, and `ensure_loaded()`
verifies the hash on every load. Attribution to the Qwen base model and
its licence is preserved in the setup documentation; CyberLLMv1 names the
fine-tuned system, not a from-scratch foundation model.

## 2. Loading: one service, one instance

`app/services/cyberllm_loader.py` (`ensure_loaded()`, module-global
bundle + lock) is the only loader. `cyberllm_inference.py` calls it
lazily; the GUI's `BackendManager` starts the same backend and never
loads weights itself. There is no second copy of the model and no
model A / model B path.

Path resolution precedence (fresh on every call):

1. `CYBERLLM_BASE_DIR` / `CYBERLLM_ADAPTER_DIR` (explicit directories).
2. `CYBERLLM_MODEL_ROOT` + `manifest.json` (base/adapter/revision/SHA).
3. Project-local `<project>/cyberLLMv1/{base,adapter}`.
4. Legacy adapter `<project>/local_models/cyberllm/v8`.

An explicit-but-incomplete `CYBERLLM_MODEL_ROOT` is a hard error: the
loader never silently falls back to a download in that case. A missing
base directory is allowed only as the Hugging Face download path (base
is ungated); a directory that exists but is incomplete fails clearly.

Device selection (`CYBERLLM_DEVICE`, default `auto`):

- `cuda` → float16, requires a CUDA GPU or a clear error.
- `cpu` → float32.
- `auto` → CUDA when available, else CPU.
- `CYBERLLM_LOAD_IN_8BIT=1` → BitsAndBytes 8-bit quantization on CUDA
  (official bitsandbytes CUDA builds; no unofficial forks). Turing
  cards (GTX 1660 SUPER) have no BF16, so the loader uses fp16 on CUDA
  and fp32 on CPU; this is why bf16-vs-fp16 numerics can flip close
  greedy decisions between environments (observed once: frozen GPU eval
  vs live CPU run on the SSRF/CVE cases — see §6).

Readiness (`GET /api/cyberllm/readiness`) reports `ready`, `state`
(`not_loaded` / `loading` / `ready`), an honest `reason`
(`not_initialized`, missing-file lists, SHA mismatch,
"PyTorch is not installed", CUDA errors), the resolved model root and
adapter directory, the adapter SHA, device, quantization, and load time.
Since this branch, artifact problems are reported before the missing-
torch problem, so an incomplete directory fails with its own actionable
message even in a torch-less venv.

## 3. Inference pipeline

`app/services/cyberllm_inference.py` (`generate()`):

- Greedy decoding, concurrency semaphore of 2, frozen trained prompt
  templates used verbatim (the 1.7B model is prompt-sensitive; templates
  must not be paraphrased).
- `enable_thinking=False` is required for Qwen3: without it the
  `<think>` trace eats the token budget (a real bug found and fixed
  during live integration testing).
- Token budgets: log / HTTP request / URL 320, vulnerability 512.
  Truncation is reported as `truncated`, never silently completed.
- Kinds: `log`, `http_request`, `url`, `vulnerability`.
  `MAX_LOG_CHARS = 8000` (input validation, `log_validation.py`).
- Output is parsed as structured JSON (keys: summary, classification,
  confidence, indicators, reasoning, limitations, recommended_actions;
  training targets add observed_facts / inferences /
  missing_information). Unparseable output is reported as
  `unparseable_output` with `raw_output` attached for inspection — never
  rewritten into a plausible-looking verdict.

## 4. Fusion: rules + model, honestly labelled

`app/services/classifier.py` (`classify_log` + `fuse_classification`):

- Rules contribute 50%, a confident model prediction 50%.
- A high-severity deterministic finding escalates `likely_benign` or
  `needs_review` to `likely_threat` transparently (deterministic
  override, recorded as such).
- These fall back to `needs_review`: model unavailable, unparseable
  output, truncated output, evidence mismatch, unjustified threat.
- `decision_source` / `source` vocab: `model`,
  `deterministic_override`, `unparseable_output`, `evidence_mismatch`,
  `truncated_output`, plus `status` values `ok` / `unavailable` /
  `error` / `unparseable` / `truncated`.
- The rules engine runs independently when inference is unavailable —
  and its verdict is labelled as rules, never as an AI verdict.
- No MITRE ATT&CK technique ID is ever emitted: the model has not
  demonstrated reliable exact-ID prediction (frozen eval T3 exact-ID
  0.025 for the best candidate), so emitting IDs would fabricate
  findings. The frozen-eval T3b abstention behaviour (refusing an ID
  when evidence is insufficient) is the supported behaviour instead.

## 5. API response schema (decision)

The mission's illustrative schema (`model` / `rules` / `assessment`
nesting) is not adopted field-for-field, because the existing schema
already carries exactly those three things distinctly, and every live
consumer (Log Analyzer page, CyberLLM page, desktop GUI client, test
suite) reads it:

| Illustrative field | Adopted field(s) |
|---|---|
| `model` (name/status/classification/summary/evidence/latency) | `classification` (source, status, classification, confidence, summary, latency_ms) and, on the CyberLLM endpoint, `model_classification`, `decision_source`, `parse_ok`, `truncated`, `output_tokens`, `raw_output` (unparseable only) |
| `rules` (status/findings) | `rules` (verdict, score, evidence) and `deterministic_findings` |
| `assessment` (status/reason) | `fusion` (score, verdict, components, note) + top-level `verdict` / `risk_score` |

Renaming to the nested shape would churn three consumers and the test
suite for no new information. The schema decision is: keep the adopted
contract, document the mapping (this table), and treat any future rename
as a breaking change requiring consumer migration first — which is the
rule the A/B removal itself followed.

## 6. The Log Analyzer "unavailable" diagnosis

The obsolete response (`model_a` / `model_b` / `fusion.model_status:
unavailable`, no CyberLLMv1 contribution) is gone: `/api/sentinel/analyze`
no longer returns `model_a`, `model_b`, `agreement`, or `prompt` fields
and no longer accepts `extra_prompt`. The old path was the
sentinel_bridge/model-A-B code that the migration removed; its
"unavailable" meant "the old models are not loaded", which was true and
unfixable by configuration because those models were never going to load
usefully (frozen eval 0.0 on every task — fluent template parrot).

On the current path, `unavailable` has exactly these causes, each
reported verbatim by readiness:

1. No model files at the resolved location (`not_initialized` /
   missing-file list) — the state in this VM.
2. Adapter SHA mismatch — refused, never loaded.
3. PyTorch not installed in the backend environment (this VM's backend
   venv has no torch; the portability test for this case now passes).
4. Explicit `CYBERLLM_MODEL_ROOT` pointing at an incomplete directory.
5. CUDA requested but unavailable, or an unknown `CYBERLLM_DEVICE`.

When files are present and valid, loading works — measured, not assumed:

- **2026-10-24 live CPU runs (this VM, real weights):** pilot v8 loaded
  in 16.3 s, peak RSS 4.53 GB; benign sudo → `likely_benign`, single SSH
  failure → `needs_review`, web scan → `likely_threat`, SSRF →
  `likely_threat`, CVE-2017-0142 → `needs_review` (valid JSON, no
  truncation). ~1.5–1.9 tok/s on 2 CPUs. Pilot v3: 13.0–19.6 s, 2.28 GB.
  Authenticated end-to-end analyze of a benign log returned 200
  `likely_benign` in 123.6 s cold.
- **Frozen eval v2.1 (GPU, pilot v8):** T5 perfect, T3b 1.00, T2 0.95,
  T1 0.9583 (one SSRF miss), T4 0.80 (one truncation), T3 exact 0.025.
  Pilot v8 is the best-measured candidate but is **not deployable-grade**
  (T1/T4 guard misses); pilot v3 remains the reference fallback and
  pilot v6 the log-analysis specialist. See the CyberLLM experiment
  registry for the full comparison.

**Real inference on this branch in this VM: NOT VERIFIED** — no weights
and no torch exist here, so readiness honestly reports `not_loaded`
(see TEST_RESULTS.md smoke run). The exact Windows verification commands
are in PORTABILITY_REPORT.md §5.

## 7. What the GUI reuses (and does not duplicate)

The desktop GUI (`security_lab/`) reuses the backend's loader, inference
service, readiness endpoint, and admin API. Its Control Center verifies
model files and adapter SHA-256 *before* load ("files present" vs
"successfully loaded" are shown as different states), displays GPU
detection, VRAM/RAM usage, logs, and diagnostic errors, and never
bundles weights or backend dependencies into the executable.
