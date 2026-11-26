# Deterministic rules (P5) and evidence check (P6)

These are **not prompts**. They are deterministic code that runs before
and after the model, so a known model weakness cannot become a clean bill
of health on its own. Source files:

- Rules: `app/services/cyberllm_rules.py` — `screen(text)`,
  `suggested_classification(findings)`.
- Evidence check: `app/services/cyberllm_evidence.py` —
  `check_evidence(input_text, model_text)`.

## Why the rules run first — the T1 item 22 blind spot

Pilot v8 has a demonstrated blind spot: in the frozen evaluation it called
an SSRF request to the cloud metadata endpoint **likely_benign with high
confidence** (frozen T1 item 22). The deterministic rules exist so that
this exact pattern can never again be waved through by the model alone.
Every rule firing cites the exact substring it matched; a rule never
invents attribution or a technique ID.

## P5 — the four rules (`screen()`)

### 1. `metadata_endpoint` — high severity

A URL in the input targets a cloud instance-metadata service. Hosts:
`169.254.169.254`, `metadata.google.internal`, `metadata.google`.
Explanation recorded with the finding: "Request targets a cloud
instance-metadata service. This is a server-side request forgery (SSRF)
pattern: metadata endpoints can disclose instance credentials. Treat as a
threat regardless of benign-looking context."

### 2. `private_fetch_target` — high severity

A URL in the input asks the server to fetch a loopback or private-network
address (an SSRF indicator). Matches host `localhost`, `0.0.0.0`, or any
host starting with `10.`, `172.16.`–`172.19.`, `172.2` (covers
`172.20.`–`172.29.`), `172.30.`, `172.31.`, `192.168.`, or `127.`
(the private/loopback prefixes as written in the code).

### 3. `credential_file_probe` — high severity

The input (case-insensitive) contains a request for a credential or
configuration file. Paths: `/.env`, `/.git/config`, `/.aws/credentials`,
`/id_rsa`, `/wp-config.php`, `/config.php`, `/.htpasswd`, `/.svn/entries`.

### 4. `repeated_probe` — medium severity

At least **4 distinct** sensitive paths appear in one submission
(case-insensitive). Paths counted: `/.env`, `/.git/`, `/wp-login.php`,
`/.aws/`, `/admin`, `/phpmyadmin`, `/.svn/`, `/backup`, `/config`. The
finding's evidence is the sorted list of matched paths. Consistent with
automated scanning.

## Suggested classification

`suggested_classification(findings)`:

- Any `high`-severity finding → `likely_threat`.
- Findings but no `high` → `needs_review`.
- No findings → `likely_benign`.

In the API (`app/api/cyberllm.py`, `analyze()`), a high-severity finding
escalates a benign or uncertain model verdict to `likely_threat`
(`decision_source: "deterministic_override"`), and the model verdict is
preserved in `model_classification` for audit. See
`detection-pipeline.md`.

## P6 — the evidence check (`check_evidence()`)

The model is not trusted for factual fields that can be read directly
from the input. Only the model's `summary`, `reasoning` and `indicators`
are checked (not `recommended_actions`, so a recommendation such as
"block port 443" is not mistaken for an observed fact). Checked only when
the input states a value unambiguously:

- Failed-attempt count (digits or words, e.g. "five failed logins").
- Time window (e.g. "within 60 seconds").
- ISO timestamp (a single unambiguous event time in the input).
- IP address (+ port) stated in the input.
- HTTP status code, only when phrased as an observed response.
- URL / domain stated in the input.
- Claimed outcome (success vs failure) when the input states one.
- Internal contradictions inside the model output itself (two different
  failed-attempt counts, or two different time windows).

A mismatch **never silently rewrites** the model's numbers to match the
input (that would hide the model's error). It downgrades the verdict to
`needs_review`, quotes the mismatch in `limitations`, and preserves the
original model classification in `model_classification`.

The API adds one more deterministic downgrade in the same place: a
high-confidence `likely_threat` with no cited indicators and less than 20
characters of reasoning is an assertion, not evidence, and is downgraded
to `needs_review` ("severity justification").
