# Evaluation Report — Sentinel Detection Quality (baseline, no retraining)

Generated: 2026-10-15 — baseline before any retraining or prompt-only fixes.

## Ground-truth set
- 26 cases in `evaluation_matrix.py` (independent, eval-only, NOT inserted into `training_examples`).
- Labels: `benign` (10, includes 2 suspicious-but-safe treated as negatives), `attack` (16).
- Categories: `benign` 10, `auth_abuse` 8, `port_scan` 1, `xss` 1, `sqli` 1, `traversal` 1, `cmdi` 1, `ssrf` 1, `ssti` 1, `upload` 1.
- Every case records: `ground_truth`, `log_text`, deterministic `rules` verdict/score/latency,
  `model_a`/`model_b` raw_text/parsed_verdict/status/tokens/latency/stopped/json_valid, `fusion`, agreement.

## Binary threat definition
- Positive GT = `attack` (16). Negative GT = `benign`+`suspicious` (10).
- Positive prediction = `needs_review` or `likely_threat`. Negative = `likely_benign` or empty (conservative).

## Results — without models (rules only)
Command: `python evaluation_matrix.py --output-dir evaluation`

```
rules:  n=26 tp=9 fp=1 tn=9 fn=7  precision 0.90  recall 0.56  F1 0.69
  benign:     1 FP (benign-07 nmap doc word)  n=10
  auth_abuse: 8/8 detected  n=8
  port_scan:  1/1 detected  n=1
  xss/sqli/traversal/cmdi/ssrf/ssti/upload: 0/1 each (rules do not score these)
  empty: 0  invalid_json: n/a
fusion (no models): same as rules (models skipped, fusion falls back to rules)
```

## Results — with models (A+B, 24 tokens, timeout 12s)
Command: `python evaluation_matrix.py --with-models --max-new-tokens 24`

```
rules:  same as above (deterministic, independent of models)
model_a: n=26 tp=0 fp=2 tn=8 fn=16  precision 0.0  recall 0.0  F1 n/a  empty 24  invalid_json 26
model_b: n=26 tp=0 fp=0 tn=10 fn=16 precision n/a recall 0.0 F1 n/a  empty 26 invalid_json 26
fusion:  n=26 tp=9 fp=1 tn=9 fn=7  precision 0.90 recall 0.56 F1 0.69  (rules 0.5 + models 0.25 each; models empty → no boost)
```

Raw Model A/B on this prompt set:
- Model A: 24 empty, 2 decoded as `likely_threat` (FP on benign-01 due to garbage decoding), timeouts on long outputs.
  Example raw fragments: `"Ġdistinct Ġusernames ..."`, `"Ġdoes Ġnot Ġperform Ġthis Ġscope ..."`, `"Ġany - authentication ."` — no structured JSON.
- Model B: 26 empty (no parsed verdict), no JSON.
- JSON schema `{verdict, category, severity, confidence, evidence[], uncertainty, limitations[]}`: **0/26 valid** for both models.

## Interpretation
- **Deterministic rules**: working for `auth_abuse` (all 8 brute-force variants, now including single-line/JSON/syslog/mixed) and `port_scan`; 1 FP on benign `nmap` doc word (acceptable for monitor-only).
- **Categories beyond rules**: expected FN (xss/sqli/traversal/cmdi/ssrf/ssti/upload). Those need detector modules (out of scope for this phase).
- **Language models**: no per-category precision/recall; do NOT independently detect any category above. Claiming model-detected `cmdi`/`ssrf`/`ssti`/etc would be fabricated.
  Prompt changes alone did not fix quality (TIMEOUT/empty/garbage). Retraining gated.
- **Fusion**: honestly reports `Models A and B are same family; agreement is not independent`. With current models empty, fusion == rules.

## Why this baseline is honest
- Labels are human-authored, model/rule-unaware.
- Evaluation data never enters training (checked by `test_evaluation_set_not_in_training_data`).
- Metrics are computed per-source, per-category, with empty/invalid tallied — small-n categories flagged `n=1` insufficient.

## Verify
```
python -m pytest tests/test_bruteforce_regression.py tests/test_evaluation_matrix.py -q
python evaluation_matrix.py
python evaluation_matrix.py --with-models --max-new-tokens 24
cat evaluation/latest.json
```

## Gating retraining
Do NOT start retraining until:
- Training data and objective are verified (80/20 per-category stratified, benign/suspicious pairs, encoding variants, multiline vs single-line; structured JSON schema validation; completion_only emits after `<output>`).
- This baseline above is the comparison point (per-category P/R/F1, ECE, empty/invalid).
- Data planapproved, objective validated by schema and rejection learning via `incident_service.update_review`.

## Artifacts
- `evaluation_matrix.py` + `evaluation/latest.json` (raw+parsed Model A/B, rules, fusion, latency, errors).
- Tests: `tests/test_bruteforce_regression.py`, `tests/test_evaluation_matrix.py` (12 existing + new pass).
