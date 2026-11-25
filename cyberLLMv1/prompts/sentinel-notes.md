# Sentinel notes (P7)

**There is no separate Sentinel LLM prompt.** Sentinel reuses the same
CyberLLM prompt templates and schema: same base model (Qwen3-1.7B), same
pilot v8 adapter, same system prompt (P1), same classification/log
templates (P2/P3), same 7-key response schema. This is stated in
`app/services/classifier.py`: "CyberLLMv1 itself is unchanged: same base,
same adapter, same prompt templates, same schema."

## How Sentinel uses CyberLLM

- `app/services/classifier.py::classify_log(text, kind="log")` is the
  single-model classifier that replaced the obsolete dual-model inference
  (previously `run_dual_inference` returned `model_a` / `model_b` texts).
  It runs `cyberllm_rules.screen()`, then `generate()`, then
  `parse_model_output()`, then `check_evidence()` — the same steps as the
  analyze API (see `detection-pipeline.md`). Unavailable / unparseable /
  truncated results are `needs_review` with confidence `low`.
- `app/services/sentinel_bridge.py::_run_analysis()` calls
  `classify_log()` plus `fuse_classification()` for security events and
  ATT&CK findings, and persists a `SentinelIncident`. Classification is
  failure-isolated: a missing model, timeout or empty result still returns
  a rules-only fusion and persists the incident with accurate model
  statuses — an absent model is never treated as success. Events are
  deduplicated (SHA-256 of IP + log head, 10-minute window) and
  idempotent (already-linked events return the existing incident).
- `app/services/classifier.py::fuse_classification()` fuses the
  deterministic rules (50%) with the CyberLLM classification (50% when
  confident). Score mapping: `likely_benign` 10, `needs_review` 50,
  `likely_threat` 85. A `needs_review` model verdict is recorded but does
  not move the fused score away from the rules. A high-severity
  deterministic finding overrides a benign model verdict (fused score at
  least 65). Fused verdict thresholds: ≥ 65 `likely_threat`, ≥ 35
  `needs_review`, otherwise `likely_benign`.

## The deterministic Sentinel layer (`app/services/security_rules.py`)

Model-independent; preserved unchanged from the old fusion, with the same
thresholds, scores and verdicts. `evaluate_rules(log_text)`:

- **IP extraction** — valid IPv4 addresses found in the text.
- **Failed-login counting** — segments the log and counts failed-login
  events across formatting variants (`login failed`, `authentication
  failed`, `401`, `403`, …). **≥ 5 failed logins → +40 points**
  (risk `auth_abuse`).
- **Successful login after failures** → **+25 points** (risk
  `success_after_fail`; possible brute-force success).
- **Port-scan indicators** — ≥ 8 distinct ports probed, or a port-scan
  keyword (`nmap`, `port scan`, `syn scan`) → **+35 points** (risk
  `port_scan`).
- Score capped at 100. Verdict: ≥ 60 `likely_threat`, ≥ 30
  `needs_review`, otherwise `likely_benign`.

## The old Sentinel model — not deployable, not used

The old dual-model Sentinel path is removed. The old Sentinel model is
**not** used for CyberLLM analysis and has no prompt to document here.
(Per the identity plan's audit, it scored 0.0 on the frozen evaluation.)
Anything that still mentions `model_a` / `model_b` is describing the
retired path, not a live model.
