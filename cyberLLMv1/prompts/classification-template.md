# Classification template (P2) — frozen

**Status: FROZEN. Do not reword.** Copied verbatim from the frozen
evaluation harness (`app/services/cyberllm_inference.py:31-36` — `CLS_TMPL`).

## Verbatim text

```text
Analyze this {kind} and respond with a JSON object with keys summary, classification (likely_benign, needs_review, or likely_threat), confidence (low, medium, or high), indicators, reasoning, limitations, recommended_actions.
{kind}: {text}
JSON:
```

- Length: **246 characters** (with the `{kind}` and `{text}` placeholders
  unsubstituted, newlines counted as single characters).
- `{kind}` is substituted from `KIND_LABELS`; `{text}` is the user's input,
  verbatim.

## `KIND_LABELS` (`app/services/cyberllm_inference.py:52-56`)

| `kind` value | Substituted `{kind}` label |
|---|---|
| `http_request` | `HTTP request` |
| `url` | `URL` |
| `vulnerability` | `vulnerability description` |

`kind == "log"` does **not** use this template — it uses the log template
(P3, `log-template.md`).

## Token budgets (`BUDGETS`, `app/services/cyberllm_inference.py:45-50`)

| `kind` | Max new tokens |
|---|---|
| `http_request` | 320 |
| `url` | 320 |
| `vulnerability` | 512 |

A generation that hits its budget is reported as `truncated` — a signal
for the schema layer, not something hidden. Truncated output is
downgraded to `needs_review` by the API (see `detection-pipeline.md`).

## Where it is used

`build_user_prompt(kind, text)` in `app/services/cyberllm_inference.py`
wraps **every** non-log input in this template before it reaches the
model, via `POST /api/cyberllm/analyze` (and therefore the Prompt Test
Lab and the Sentinel classifier, which call the same paths). The model
must answer as a JSON object with exactly the seven keys listed in the
template: `summary`, `classification`, `confidence`, `indicators`,
`reasoning`, `limitations`, `recommended_actions`.

Note the consequence, documented honestly: because every input is wrapped
in this template, a free-form question (for example an identity question
such as "Who developed you?") is analysed as if it were a URL / HTTP
request / vulnerability description. That is failure mode A in the
identity plan — the production-path identity probes score 3/12, against
7/12 when the raw text is passed to the model directly. The fix for that
is a deterministic identity path in the API, not a change to this
template.

## Worked example — URL

Input: `kind = "url"`, text =
`http://login-secure-update.example.com/verify-account`

The full user prompt sent to the model (after the system prompt, P1) is:

```text
Analyze this URL and respond with a JSON object with keys summary, classification (likely_benign, needs_review, or likely_threat), confidence (low, medium, or high), indicators, reasoning, limitations, recommended_actions.
URL: http://login-secure-update.example.com/verify-account
JSON:
```

The model is expected to reply with a JSON object only, for example (illustrative shape, not a recorded output):

```json
{
  "summary": "URL impersonates a login verification page on an unrelated domain.",
  "classification": "likely_threat",
  "confidence": "high",
  "indicators": ["unrelated domain for a login page", "verify-account path typical of phishing"],
  "reasoning": "The domain does not match any known service and the path pressures the user to verify an account.",
  "limitations": ["Domain reputation was not checked against an external feed."],
  "recommended_actions": ["Do not open the link.", "Report it as phishing."]
}
```
