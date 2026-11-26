# Identity fine-tune v3 — `v8-identity` (P10)

> **HISTORICAL — FAILED, NOT PROMOTED.** This documents a dead end, so
> nobody retries the same recipe. The original pilot v8 adapter remains
> the production model and is never overwritten.

## Source

`cyberLLMv1/MODEL_CARD.md` — "Identity version (evaluated — not
promoted)".

## What it was

`v8-identity`: a continued LoRA fine-tune of pilot v8 on **56 authored
identity examples**, teaching the model to identify as CyberLLM,
developed by Gaurav Singh, through training rather than only through the
system prompt. (The 56 identity examples are preserved in the CyberLLM
workspace.)

## What happened

Trained and evaluated **2026-11-13** (the v3 run). Adapter SHA-256:
`190b12aa94b46e38647f6426511178686b3e1ad857ca4b08c123bb2e9fb282fb`.

It **failed the comparison gate**:

- **0.0 on every frozen eval task and val-v3** — all 193 JSON-task
  generations truncated in a `:`-repetition collapse. The fine-tune
  destroyed the model's ability to produce the required JSON at all.
- **T13 identity pass 0.2** (v8: 1.0).
- **Held-out identity probes 2/12** (v8: 4/12) — worse than the base v8
  adapter it was supposed to improve.

## Why it is not retried as configured

The recipe as configured is a dead end: a small identity-only fine-tune
with no security-data replay collapsed generation stability. The working
identity mechanism is the deployment system prompt (P1, naming Gaurav
Singh) plus code-level handling (a deterministic identity path and output
sanitiser — plan §1). Identity fine-tuning was abandoned in favour of
system-prompt identity plus code-level enforcement.

Any future identity retry needs a **redesigned recipe** (for example
security-data replay alongside the identity examples, and far fewer
steps) **and fresh approval**. Do not re-run this recipe, do not promote
the `v8-identity` adapter, and do not overwrite v8 with it.
