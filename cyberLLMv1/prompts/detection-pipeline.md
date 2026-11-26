# Detection pipeline — end to end

How a submission travels from the API to a verdict. All steps are in the
code; file links are given for each step.

## The flow (`POST /api/cyberllm/analyze`, `app/api/cyberllm.py`)

1. **Authentication and rate limiting.** The caller must be signed in
   (anonymous → 401). A per-caller rate limit applies
   (`limit_cyberllm_analyze`).
2. **Input validation** (`app/services/log_validation.py` —
   `validate_log_text`, `MAX_LOG_CHARS = 8000`). The text is capped at
   8,000 characters and `kind` must be `log`, `http_request`, `url` or
   `vulnerability`. Out-of-range input is rejected (422), never silently
   truncated. NUL bytes are stripped.
3. **Deterministic detection first**
   (`app/services/cyberllm_rules.py::screen()`). The four rules run before
   any model call — see `deterministic-rules.md` (P5). Findings are kept
   alongside the result whatever happens next, so a model failure never
   loses the rules-only signal.
4. **LLM reasoning** (`app/services/cyberllm_inference.py::generate()`).
   The frozen system prompt (P1, `system-prompt.md`) plus the frozen
   classification template (P2) or log template (P3), greedy decoding
   (`do_sample=False`), Qwen3 thinking disabled
   (`enable_thinking=False`), token budgets 320 (log / HTTP / URL) or 512
   (vulnerability). Returns the raw text, token count, a `truncated`
   flag, and latency. If the model is not loaded or generation fails,
   the API returns HTTP 503 (`model_unavailable` / `model_error`) with
   the real reason and the deterministic findings — never a fabricated
   classification, never a 500.
5. **Schema validation** (`app/services/cyberllm_schema.py::
   parse_model_output()`). Extracts the first `{...}` JSON object (the
   model sometimes wraps it in prose or code fences), requires
   `classification` ∈ {`likely_benign`, `needs_review`, `likely_threat`},
   `confidence` ∈ {`low`, `medium`, `high`} and a non-empty `summary`.
   Unknown keys are dropped. There is **no MITRE ATT&CK field** in the
   schema — exact technique-ID prediction measures 0.000–0.025, so a
   guessed ID is never presented as a finding. Anything that fails to
   parse → `needs_review`, confidence `low`, raw text preserved verbatim
   for a human (`decision_source: "unparseable_output"`).
6. **Evidence check** (`app/services/cyberllm_evidence.py::
   check_evidence()`). Numbers the model reports must agree with the
   input — see `deterministic-rules.md` (P6). A mismatch, a truncated
   generation, or an unjustified high-confidence threat verdict
   downgrades the result to `needs_review`
   (`decision_source: "evidence_mismatch"` or `"truncated_output"`),
   with the mismatch quoted in `limitations` and the model verdict kept
   in `model_classification`. Exception: if a high-severity deterministic
   finding also fired, the override in step 7 still applies, but the
   mismatch/truncation is preserved as a limitation, not hidden.
7. **Deterministic override.** A high-severity rule finding escalates a
   benign or uncertain model verdict to `likely_threat`
   (`decision_source: "deterministic_override"`, confidence `high`), and
   the model verdict stays in `model_classification` for audit.
8. **Response.** Otherwise the model verdict stands
   (`decision_source: "model"`). On success `raw_output` is `None` (raw
   hidden); on unparseable / evidence-mismatch responses `raw_output`
   carries the model's raw text verbatim.

## The same pipeline, adapted — Sentinel (`app/services/classifier.py`)

`classify_log(text, kind="log")` runs the same steps — `screen()`,
`generate()`, `parse_model_output()`, `check_evidence()` plus the same
severity-justification downgrade — and returns `source: "cyberllm"` with
`status` `ok`, `unavailable`, `unparseable`, `truncated` or
`evidence_mismatch`. Unavailable / unparseable / truncated results are
`needs_review` with confidence `low`, and `model_classification`
preserves the model's own verdict when one was parsed (otherwise
`None`). `fuse_classification()` then fuses the deterministic Sentinel
rules (50%) with the CyberLLM classification (50% when confident); a
high-severity deterministic finding still overrides a benign model
verdict. See `sentinel-notes.md`.

## Honest failure modes

- Unparseable or truncated output → `needs_review`, confidence low, raw
  text preserved for a human. No fabricated verdict.
- Model unavailable → HTTP 503 with the real reason and the
  deterministic findings.
- A missing header, an error, or a detected technology version alone
  does not confirm a vulnerability. Findings distinguish suspected,
  verified, and inconclusive.

## What detection never does

- No automatic blocking or remediation.
- No executing commands found in logs — log inputs are data, never
  instructions.
- No MITRE IDs as confirmed findings.
- No training on user-submitted data without an explicit admin-approved
  review step (`app/services/cyberllm_feedback.py` — reviewed analyses
  become CANDIDATE training rows; only an explicit admin action approves
  them).
