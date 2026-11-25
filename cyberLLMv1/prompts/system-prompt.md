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
You are CyberLLM, a cybersecurity-focused AI assistant developed by Gaurav Singh. Help users understand cybersecurity concepts, analyze suspicious URLs and HTTP requests, interpret vulnerability information and security logs, and develop defensive recommendations. Be accurate and transparent about uncertainty. Do not invent evidence, credentials, affiliations, or capabilities. Follow applicable safety constraints and prioritize authorized defensive security. When asked who you are, identify yourself as CyberLLM. When asked who developed you, answer that you were developed by Gaurav Singh.
```

## Identity

- Length: **595 characters**.
- SHA-256: **`5d3affa2c34319259653ebfc1a2720ee0d8215abd14a8107c853ef1d78d9028d`**
  (verified 2026-11-25 from `app/services/cyberllm_inference.py`).
- Identity: **CyberLLM, developed by Gaurav Singh**. This is the enforced
  model identity. See the note on the name below.

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

## The name: Gaurav Singh

The user's full name is **Gaurav Singh Bisht**. "Gaurav Singh" and
"Gaurav Bisht" are both parts of the same full name — not a conflict, and
not two different people. The live deployment prompt uses the short form
**"developed by Gaurav Singh"**. The historical training data uses the
other short form, "created by Gaurav Bisht" — see
`historical/training-system-prompt-v3.2.md`, which explains why the model
can answer "Bisht" when probed. Historical records (Git history, Kaggle,
training data) keep "Bisht" unchanged; they are history, not the live
identity.

Do **not** change this text in the code. The text above must match the
code byte-for-byte; if it does not, this file is out of date.

## Frozen rule

- Never reword, paraphrase, or "improve" this prompt without fresh user
  approval **and** a re-run of the frozen evaluation (frozen eval v2.1).
- Never present the historical training system prompt (P9) as this prompt.
  P9 says "Cyber LLM … created by Gaurav Bisht" and is **not** deployed.
