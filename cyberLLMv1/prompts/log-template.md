# Log template (P3) — frozen

**Status: FROZEN. Do not reword.** Copied verbatim from the frozen
evaluation harness (`app/services/cyberllm_inference.py:38-43` — `LOG_TMPL`).

## Verbatim text

```text
Analyze this security log and respond with a JSON object with keys summary, classification (likely_benign, needs_review, or likely_threat), confidence (low, medium, or high), indicators, reasoning, limitations, recommended_actions.
Log:
{text}
JSON:
```

- Length: **249 characters** (with the `{text}` placeholder unsubstituted,
  newlines counted as single characters).
- `{text}` is the user's log input, verbatim.

## Token budget (`BUDGETS`, `app/services/cyberllm_inference.py:45-50`)

| `kind` | Max new tokens |
|---|---|
| `log` | 320 |

A generation that hits its budget is reported as `truncated` — a signal
for the schema layer, not something hidden. Truncated output is
downgraded to `needs_review` by the API (see `detection-pipeline.md`).

## Where it is used

`build_user_prompt(kind, text)` in `app/services/cyberllm_inference.py`
uses this template when `kind == "log"`, for **every** log input, via
`POST /api/cyberllm/analyze` (and therefore the Prompt Test Lab and the
Sentinel classifier, which call the same paths). The model must answer as
a JSON object with exactly the seven keys listed in the template:
`summary`, `classification`, `confidence`, `indicators`, `reasoning`,
`limitations`, `recommended_actions`.

Log inputs are data to analyse, never instructions to run: commands found
inside a submitted log must never be executed.

## Worked example — SSH brute-force log

Input: `kind = "log"`, text =

```text
Nov 25 09:12:01 srv-01 sshd[1234]: Failed password for root from 203.0.113.45 port 51234 ssh2
Nov 25 09:12:04 srv-01 sshd[1234]: Failed password for root from 203.0.113.45 port 51235 ssh2
Nov 25 09:12:07 srv-01 sshd[1234]: Failed password for root from 203.0.113.45 port 51236 ssh2
Nov 25 09:12:10 srv-01 sshd[1234]: Failed password for root from 203.0.113.45 port 51237 ssh2
Nov 25 09:12:13 srv-01 sshd[1234]: Failed password for root from 203.0.113.45 port 51238 ssh2
```

(The IP `203.0.113.45` is a documentation address from TEST-NET-3; the
log lines are a constructed example, not a recorded incident.)

The full user prompt sent to the model (after the system prompt, P1) is:

```text
Analyze this security log and respond with a JSON object with keys summary, classification (likely_benign, needs_review, or likely_threat), confidence (low, medium, or high), indicators, reasoning, limitations, recommended_actions.
Log:
Nov 25 09:12:01 srv-01 sshd[1234]: Failed password for root from 203.0.113.45 port 51234 ssh2
Nov 25 09:12:04 srv-01 sshd[1234]: Failed password for root from 203.0.113.45 port 51235 ssh2
Nov 25 09:12:07 srv-01 sshd[1234]: Failed password for root from 203.0.113.45 port 51236 ssh2
Nov 25 09:12:10 srv-01 sshd[1234]: Failed password for root from 203.0.113.45 port 51237 ssh2
Nov 25 09:12:13 srv-01 sshd[1234]: Failed password for root from 203.0.113.45 port 51238 ssh2
JSON:
```

The model is expected to reply with a JSON object only, for example (illustrative shape, not a recorded output):

```json
{
  "summary": "Five failed SSH login attempts for root from a single IP within 12 seconds.",
  "classification": "likely_threat",
  "confidence": "high",
  "indicators": ["5 failed password attempts", "single source IP 203.0.113.45", "target account is root", "12-second window"],
  "reasoning": "Repeated failed logins for a privileged account from one IP in a short window match a brute-force pattern.",
  "limitations": ["No information about whether any login later succeeded."],
  "recommended_actions": ["Block or rate-limit 203.0.113.45.", "Review whether root SSH login should be disabled."]
}
```

The deterministic layers also see this input: the Sentinel rules in
`app/services/security_rules.py` count 5 failed logins (threshold 5) and
the CyberLLM rules in `app/services/cyberllm_rules.py` do not fire on it
(no metadata URL, private fetch target, credential-file path, or
repeated sensitive-path probe). See `deterministic-rules.md`.
