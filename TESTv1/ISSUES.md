# ISSUES — SentientAI (2026-10-20)

> Defect log. Each row verifiable from evidence in `evidence/`, `logs/`, or a reproduction on `http://127.0.0.1:8000`. No invented results.

| ID | Title | Severity | Component | Repro steps | Expected | Actual | Evidence | Status |
|---|---|---|---|---|---|---|---|---|
| — | (no issues recorded yet; workers append here phase by phase) | — | — | — | — | — | — | — |

## Severity
- **Critical** — data loss, auth bypass, SSRF/RCE, session hijack confirmed.
- **High** — privilege escalation, stored XSS, IDOR, rate-limit bypass.
- **Medium** — functional bug with user impact, missing validation, broken flow.
- **Low** — cosmetic, copy, minor UX.
- **Info** — observation, not a defect.

## Status
`Open` → `Fix pending` → `Fixed (verified)` / `Won't fix` / `Blocked`. `FIX_LOG.md` links `Issue ID → Files changed → Verification`.

## Evidence naming
Screenshots `evidence/screenshots/<issue-id>_<slug>.png`, browser traces `evidence/browser/`, logs `logs/`, exports `test-data/`.
