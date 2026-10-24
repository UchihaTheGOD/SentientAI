# SentinelAI Dataset Requirements — 96M SentinelModel (vocab 7053, max_pos 768)

This document defines exactly what Sentinel must learn, what input/target shapes are required, and how each task is measured. It governs phases 2/6/7 and the Kaggle pilot.

## Model-realities (architecture constraints)

- Architecture: `SentinelModel` — TransformerEncoder 12 layers, 12 heads, hidden 768, intermediate 3072, tied `lm_head`, `max_position_embeddings=768`, vocab 7053, specials `<pad>0 <unk>1 <bos>2 <eos>3 <instruction>4 </instruction>5 <input>6 </input>7 <output>8 </output>9`.
- Training contract in saved checkpoints: `completion_only=True`, `max_length=768`. Only tokens **after** final `<output>` receive loss (instruction + input are masked). Every example must be rendered as `<instruction>{instruction}</instruction><input>{sanitized_log}</input><output>{target}</output>` where `<output>` is kept at tail via truncation budget `max_pos-max_new-4` (see `sentinel_inference.py`).
- Token-length budget: keep serialized prompt + target ≤ 740 tokens to leave 96 for generation + 4 guard tokens. Validation must reject examples that tokenise >768.
- Tokenizer coverage: all target strings must be encodable by `sentinel_tokenizer.json`; any target containing characters outside vocab becomes `<unk>` and will be penalised — validation must flag >5% unk in target.

Why the 96M model failed: checkpoints were fine-tuned for free-form analyst prose, not for the structured moderation JSON / structured analysis required by `sentinel_moderation.py` and `sentinel_schema.py`. Logits now favour generic shards over schema keywords (see `Documentation/SENTINEL_DIAGNOSTIC_REPORT.md`). Only supervised fine-tuning on validated structured targets can fix this; longer training on prose will not.

## The 12 capabilities — what must be learned, and what is out of scope for this LM

The moderation + analysis contracts actually used in the app are **structured**:

- Moderation JSON (single task the app consumes): `{"label":"likely_benign|needs_review|likely_threat","category":"benign|spam|harassment|prompt_injection|ambiguous|unknown|auth_abuse|port_scan|xss|sqli|traversal|cmdi|ssrf|ssti|upload","confidence":0-1,"evidence":["..."],"uncertainty":0-1,"reasoning_summary":"..."}` validated by `sentinel_moderation.validate_moderation_json`.
- Analysis prose (optional): `Summary / Input status / Indicators / Reasoning / Provisional assessment / Recommendation` validated by `sentinel_schema.validate_sentinel_output`.

All 12 mission tasks map onto **one LM task** (produce one of those two structured outputs from a sanitized log). Tasks 3-7 do **not** need separate detectors; they are categories / evidence inside the structured output. No new architecture is required. Separate detectors would add surface and are intentionally **not** introduced until evaluation shows a single LM cannot separate categories.

| # | Mission task | What the LM must emit | Labels required | Input shape | How success is measured |
|---|--------------|-----------------------|-----------------|-------------|--------------------------|
| 1 | Security-log interpretation | `Indicators:` bullets grounded in input | `valid|empty|malformed|insufficient_evidence` | one sanitized log line(s) in `<input>` | section-present rate; no fabricated indicator |
| 2 | Benign vs suspicious classification | `label` | `likely_benign|needs_review|likely_threat` | same | per-label precision/recall/F1; confusion matrix |
| 3 | SQL injection detection | `category=sqli` + evidence citing payload | sqli / not-sqli | HTTP request / query string log | category F1, FP on `SELECTION` benign |
| 4 | XSS detection | `category=xss` | xss / not-xss | HTTP log with payload | category F1 |
| 5 | Path traversal detection | `category=traversal` | traversal / not-traversal | path / URL log | category F1, FP on `etc/passwd` without traversal |
| 6 | Authentication abuse detection | `category=auth_abuse` + failed-count reasoning | auth_abuse / not | auth log lines | category F1 |
| 7 | Port-scan / reconnaissance detection | `category=port_scan` + port-list evidence | port_scan / not | network log | category F1 |
| 8 | Evidence extraction | `evidence: ["..."]` 1-6 items, ≤300 chars each | string list grounded in input | same | evidence-groundedness: every evidence substring appears verbatim in input (case-insensitive) |
| 9 | Severity assessment | `severity` via `sentinel_schema` / `label` mapping | mapped severity | same | label-vs-severity consistency |
| 10 | Structured incident explanation | `reasoning_summary` 1-800 chars | free text, grounded | same | reasoning not inventing indicators |
| 11 | Uncertainty handling | `uncertainty` 0-1 + `needs_review` when uncertain | float + label | ambiguous log | `needs_review` rate on ambiguous >0.6; calibration vs human |
| 12 | Recommendations | `Recommendation:` line in prose variant | one-sentence next step | same | present & non-generic on threat cases |

## Required example schema (training_factory convention, mirrors `training_example` table)

```json
{
  "example_id": "sha256(instruction+input)[:16]",
  "source_dataset": "csic2010|kaggle-cyber|synthetic|moderation",
  "task": "moderation_json | analysis_structured",
  "instruction": "<instruction> text — copied from prompts/prompt.txt snapshot + per-task task line",
  "input": "<sanitized log, credentials/tokens/PII scrubbed, control tokens bracketed, ≤1500 chars>",
  "output": "{\"label\":\"...\",\"category\":\"...\",\"confidence\":0.72,\"evidence\":[\"...\"],\"uncertainty\":0.31,\"reasoning_summary\":\"...\"} OR structured prose",
  "labels": {"label":"likely_benign","category":"benign","verdict":"likely_benign"},
  "evidence": ["<verb-substring of input>"],
  "uncertainty": 0.3,
  "license": "CC-BY-4.0 | MIT | CDLA-Permissive | etc — verified, never invented",
  "provenance": {"file": "raw/web/csic2010.jsonl", "line": 123, "hash": "sha256"}
}
```

- `instruction` is the same prompt snapshot for every example in a run (recorded in manifest). Never silently mix prompts inside a split.
- Every `evidence` entry must be a substring of `input` (checked by validator). Failure = reject to `datasets/rejected/`.
- `output` must pass `validate_moderation_json` (JSON variant) or `validate_sentinel_output` (prose variant). Failure = reject.
- Tokenised length `len(tokenizer.encode(instruction+input+output).ids) ≤ 768`; otherwise reject or truncate with audit trail (never silently drop tail `<output>`).
- `synthetic` examples must carry `"synthetic": true` and be counted separately; they may not dominate any split (>20%).

## Minimum validation & split requirements

- Splits: 80 train / 10 validation / 10 test, stratified by `category`; test is written once and isolated from model selection (never used for training, tuning, or self-training acceptance).
- De-duplication: `dedup_hash = sha256(normalized instruction+input)`; exact dup across splits = leakage → reject and report. Near-dup detection via `difflib ratio >0.92` is advisory and flagged in `reports/data_quality.json`.
- Class balance: no category may be <5% of train unless documented as known limitation with oversampling plan; report distribution in `reports/class_distribution.json`.
- Token coverage: report `unk_rate` per split; reject split with mean target unk_rate >0.05.
- Leakage checks: hash overlap train↔test, n-gram overlap, IP/user overlap warnings.

## How each task's sufficiency is judged (acceptance gates)

- Valid structured-output rate on held-out test ≥ 0.60 for JSON and ≥ 0.50 for prose (today: 0.0).
- Macro F1 across categories ≥ 0.55 on test; no single attack category <0.35.
- Benign F1 ≥ 0.70 (FP budget is tight: FP on benign costs more than FN on threat because human review is the gate).
- Ambiguous set: ≥60% labelled `needs_review` with `uncertainty>0.5`.
- Evidence groundedness pass rate ≥ 0.90.
- Empty-output rate ≤ 0.10 on test; repetition rate ≤ 0.05.

A dataset is not "sufficient because large" — sufficiency is meeting the gates above on **held-out** data.

## What not to collect

- Private user logs, production DB dumps, credentials, secrets — never uploaded or collected.
- Unlicensed scraped logs; only datasets whose license explicitly permits research/redistribution.
- Random cybersecurity PDFs to inflate counts — rejected at manifest stage.
