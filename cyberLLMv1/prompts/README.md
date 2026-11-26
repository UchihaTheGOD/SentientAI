# CyberLLM prompts

Documentation of the exact prompts CyberLLM pilot v8 is given at runtime,
copied verbatim from the code, plus the deterministic layers that run
around the model. Nothing in this folder is invented: every prompt text
traces to a verified code location listed in its file.

## Files

| File | What it is |
|---|---|
| `system-prompt.md` | P1 — the frozen deployment system prompt (verbatim). |
| `classification-template.md` | P2 — the template for `http_request` / `url` / `vulnerability` inputs (verbatim), with a worked URL example. |
| `log-template.md` | P3 — the template for `log` inputs (verbatim), with a worked SSH brute-force example. |
| `deterministic-rules.md` | P5 — the four deterministic rules in `cyberllm_rules.py` — plus P6, the evidence check in `cyberllm_evidence.py`. These are not prompts; they run before/after the model. |
| `detection-pipeline.md` | The end-to-end flow: validate → screen → generate → parse → evidence → override → response. |
| `sentinel-notes.md` | P7 — Sentinel reuses these same CyberLLM templates; there is no separate Sentinel LLM prompt. |
| `test-lab.md` | P8 — the Prompt Test Lab: how to test prompts against the real model. |
| `historical/training-system-prompt-v3.2.md` | P9 — HISTORICAL. The system prompt baked into the Data-v3.2 training rows. Not the live prompt. |
| `historical/identity-finetune-v3.md` | P10 — HISTORICAL. The 56-example identity fine-tune (`v8-identity`) that failed and was not promoted. |

## Frozen-status warning

**P1, P2 and P3 are frozen. Do not reword them.**

They are copied exactly from the frozen evaluation harness that produced
pilots v2–v8 (`app/services/cyberllm_inference.py`). Pilot v8 is
prompt-sensitive: paraphrased prompts route it to prose answers instead of
the required JSON (the pilot v4 lesson). Even a one-sentence amendment to
the system prompt was tried and made evaluation worse (the v2 re-run,
2026-11-14); the amendment path is closed. Any change to these prompts
needs fresh approval **and** a re-run of the frozen evaluation — never a
silent edit.

## Code is the source of truth

No code imports these Markdown files. The code stays the single source of
truth; this folder is documentation only. If a file here and the code
disagree, the code is right and this folder is wrong — fix the docs, never
the code, to match.

## How to verify against code

Run the drift test from the repo root:

```bash
python -m pytest tests/test_prompt_docs.py -v
```

It reads `cyberLLMv1/prompts/*.md` and asserts that `SYSTEM_PROMPT`,
`CLS_TMPL` and `LOG_TMPL` from `app/services/cyberllm_inference.py`
appear verbatim in these docs.

Manual checks:

```bash
# SYSTEM_PROMPT SHA-256 must still be:
# c58e3f577b7eb8270eb8468a756175adc9a4617dc39cdee91bb04f81b8328f07 (591 chars)
python -c "import hashlib; from app.services.cyberllm_inference import SYSTEM_PROMPT; print(len(SYSTEM_PROMPT)); print(hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest())"

# CLS_TMPL is 246 chars, LOG_TMPL is 249 chars
python -c "from app.services.cyberllm_inference import CLS_TMPL, LOG_TMPL; print(len(CLS_TMPL), len(LOG_TMPL))"
```

## What is deliberately NOT in this folder

- **Demo cases** (`app/services/demo_cases.py`): 10-category controlled
  test cases against real app routes (sqli, xss, traversal, auth, access,
  csrf, methods, rate-limit, headers-cookies, info-disclosure). They are
  route tests, not LLM prompts.
- **The old Sentinel model**: it has no prompt to document. Sentinel
  reuses the CyberLLM templates (see `sentinel-notes.md`).
- **Any prompt not in the code.** If it is not in
  `app/services/cyberllm_inference.py`, it is not documented here as a
  live prompt.
