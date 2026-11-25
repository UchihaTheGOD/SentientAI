# Prompt Test Lab (P8)

The Prompt Test Lab is a **testing surface, not a prompt template**. It
sends whatever the user types to the real model through the existing
backend API and records the result. There is no separate Lab prompt.

## Source

`security_lab/gui/page_testlab.py` — desktop Security Lab page
("Prompt & Output Test Lab").

## How it works

- The user types any prompt — a security log, an HTTP request, a URL, or
  a vulnerability description — picks a mode (`log`, `http_request`,
  `url`, `vulnerability`) and a max-new-tokens value (16–512, default
  320), and the page calls `POST /api/cyberllm/analyze` through the Lab's
  API client (`InferenceWorker`). Sign-in is required first.
- Generation is **greedy / deterministic** in the backend. There is no
  temperature, top-p, top-k or repetition-penalty control — the API does
  not accept those parameters, so the page does not offer them. The only
  generation setting is `max_new_tokens`.
- The **system prompt is applied server-side and is not exposed by the
  API**. The page shows the deployed prompt only when it can be read from
  the local project copy; otherwise it says so instead of inventing one.
- Every run is recorded: prompt, model (CyberLLM Pilot v8), adapter
  SHA-256, timestamp, settings, raw output, parsed structured output,
  duration, output tokens, JSON validity, and schema compliance
  (all 7 required keys present).
- History is stored locally as JSONL in the Lab data directory
  (`test_lab_history.jsonl`) and never leaves the machine. Prompts may
  contain sensitive log data — "Clear history" wipes it. No secrets are
  ever recorded.
- Any two history rows can be compared: the page lists which of kind,
  classification, confidence, output tokens, latency and JSON validity
  differ, and shows both raw outputs side by side.

## Identity questions go through `analyze` — and that is a known limitation

Because the Lab calls `POST /api/cyberllm/analyze`, every free-form
question typed here is wrapped in the classification or log template
(P2/P3) before it reaches the model — exactly like any other analyze
call. So an identity question such as "Who developed you?" used to be
analysed as if it were a log line or a URL, and the model answered with
a classification of the question instead of answering it. That is failure
mode A in the identity plan: production-path identity probes scored 3/12,
against 7/12 when raw text is passed to the model directly.

The fix is implemented (2026-11-25): a deterministic identity-question
path in `analyze()` recognises identity questions and answers them
directly without calling the model (`decision_source: "identity_rule"`),
so the Lab now answers identity questions correctly too, because it calls
the same endpoint. The 12 probes have not yet been re-run through the
production path, so 3/12 remains the last measured production figure
until that re-run.
