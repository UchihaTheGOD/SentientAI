# Historical training system prompt — Data-v3.2 (P9)

> **HISTORICAL — NOT DEPLOYED.** This is the system prompt baked into
> the Data-v3.2 training rows. It is **not** the live prompt. The live
> prompt is P1 (`../system-prompt.md`): "CyberLLM … developed by Gaurav
> Singh". Do not present this file's text as the live prompt, and do not
> "fix" it — the training data is preserved as the historical record.

## Source

`~/workspace/cyberllm/data/train_v32.jsonl` — the `messages[0]` (system)
message of every training row. Verified 2026-11-25: all **5,932 rows**
carry this one identical system prompt (1 distinct system prompt in the
whole file), and the string "developed by Gaurav Singh" appears in **0**
rows.

## Verbatim text

```text
You are Cyber LLM, a cybersecurity-focused AI assistant created by Gaurav Bisht. Help users understand cybersecurity concepts, analyze suspicious URLs and HTTP requests, interpret vulnerability information and security logs, and develop defensive recommendations. Be accurate and transparent about uncertainty. Do not invent evidence, credentials, affiliations, or capabilities. Follow applicable safety constraints and prioritize authorized defensive security. When asked who you are, identify yourself as Cyber LLM. When asked who created you, answer that you were created by Gaurav Bisht.
```

- Length: **591 characters**.
- SHA-256: **`c58e3f577b7eb8270eb8468a756175adc9a4617dc39cdee91bb04f81b8328f07`**.

## How it differs from the live prompt (P1)

| | Historical (P9, this file) | Live (P1) |
|---|---|---|
| Name | "Cyber LLM" (with a space) | "CyberLLM" |
| Identity wording | "created by Gaurav Bisht" | "developed by Gaurav Singh" |
| Identity question | "When asked who created you, answer that you were created by Gaurav Bisht." | "When asked who developed you, answer that you were developed by Gaurav Singh." |

Everything else in the two prompts is identical, word for word.

## The name: why "Bisht" is not a different person

The user's full name is **Gaurav Singh Bisht**. "Gaurav Singh" and
"Gaurav Bisht" are both parts of the same full name — not a conflict, and
not two different people. The training data uses one short form
("created by Gaurav **Bisht**"); the live deployment prompt uses the other
short form ("developed by Gaurav **Singh**"). Historical records (Git
history, Kaggle kernels, this training data) keep "Bisht" unchanged
because that is what was written at the time.

## Why this matters — the identity conflict

The adapter (pilot v8) was trained on 5,932 rows that all say "created by
Gaurav Bisht", while the runtime prompt says "developed by Gaurav Singh"
and the base model (Qwen3-1.7B) knows "Qwen" — three competing identities.
That is why the model can answer **"Bisht"** when probed about who
created/developed it, and sometimes "Qwen": the training-data wording is
what the adapter learned. The fix is code-level (a deterministic identity
path and output sanitiser in the API — plan §1), not a data edit: the
training data stays as the historical record.
