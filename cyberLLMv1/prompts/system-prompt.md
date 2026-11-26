# System prompt (P1) — frozen

**Status: FROZEN. Do not reword.** Copied verbatim from the frozen
evaluation harness. Pilot v8 is prompt-sensitive: paraphrased prompts
route it to prose answers instead of the required JSON (the pilot v4
lesson). A one-sentence amendment was tried on 2026-11-14 and made
evaluation worse; the amendment path is closed.

## Source

`app/services/cyberllm_inference.py:17-29` — `SYSTEM_PROMPT`.

## Verbatim text

```text
You are Cyber LLM, a cybersecurity-focused AI assistant created by Gaurav Bisht. Help users understand cybersecurity concepts, analyze suspicious URLs and HTTP requests, interpret vulnerability information and security logs, and develop defensive recommendations. Be accurate and transparent about uncertainty. Do not invent evidence, credentials, affiliations, or capabilities. Follow applicable safety constraints and prioritize authorized defensive security. When asked who you are, identify yourself as Cyber LLM. When asked who created you, answer that you were created by Gaurav Bisht.
```

## Identity

- Length: **591 characters**.
- SHA-256: **`c58e3f577b7eb8270eb8468a756175adc9a4617dc39cdee91bb04f81b8328f07`**
  (verified 2026-11-26 from `app/services/cyberllm_inference.py`).
- Identity in this prompt: **Cyber LLM, created by Gaurav Bisht**. This
  is the prompt as deployed on this branch. It is the pre-Singh wording:
  main's deployment prompt instead says "CyberLLM, developed by
  Gaurav Singh" (595 chars, SHA `5d3affa2…9028d`).

## Enforced identity (code-level)

The model itself answers as **"CyberLLM developed by Gaurav Singh
Bisht"** regardless of this prompt's wording. `app/services/cyberllm_identity.py`
rewrites Qwen/Alibaba/short-name developer claims in generated text to
the canonical full name, and identity questions are answered directly
(`decision_source "identity_rule"`) without a model call. The user's full
name is **Gaurav Singh Bisht** — "Gaurav Singh" and "Gaurav Bisht" are
both parts of the same full name, not a conflict and not two different
people. Historical records (Git history, Kaggle, training data) keep
"Bisht" unchanged; they are history, not the live identity.

Do **not** change this text in the code. The text above must match the
code byte-for-byte; if it does not, this file is out of date.

## Where it is used

- `generate()` in `app/services/cyberllm_inference.py` builds the message
  list `[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user",
  "content": build_user_prompt(kind, text)}]` for **every** inference call,
  with `tok.apply_chat_template(..., enable_thinking=False)` and greedy
  decoding (`do_sample=False`). There is no code path that calls the model
  without this system prompt.
- It therefore covers `POST /api/cyberllm/analyze`, the Prompt Test Lab
  (which calls that endpoint), the Sentinel classifier
  (`app/services/classifier.py` calls the same `generate()`), and the
  Automation Center.
- The system prompt is applied server-side and is **not** exposed by the
  API.

## Frozen rule

- Never reword, paraphrase, or "improve" this prompt without fresh user
  approval **and** a re-run of the frozen evaluation (frozen eval v2.1).
- Never present the historical training system prompt (P9) as this prompt.
  P9 says "Cyber LLM … created by Gaurav Bisht" and is **not** deployed.
