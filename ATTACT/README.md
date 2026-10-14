# ATTACT — Authorized Website Security Assessment Toolkit

Modular, read-only, low-rate checks against a locally-running or explicitly authorized web app. Never modifies data, steals secrets, or does DoS.

## Scope & Authorization

- Needs both `--target <URL>` and `--confirm-authorized`.
- Loopback by default (`127.0.0.1`, `::1`, `localhost` / resolved loopback). Other hosts must be in `--allowlist` (comma-separated).
- Every URL and redirect hop is resolved via `getaddrinfo` + `ipaddress` and revalidated. `0.0.0.0`, creds-in-URL, DNS-rebinding bypasses are rejected.
- Only `http`/`https`, sequential requests, per-request `--timeout`, global `--max-requests`, and a `stop()` mechanism.
- Never prints/transmits passwords or tokens — evidence is redacted.

## Install

No extra deps — stdlib `urllib` only. With SentientAI venv active:

```
python -m ATTACT --help
```

## Checks (12)

`security_headers`, `cookie_security`, `xss`, `sqli`, `path_traversal`, `auth_session`, `access_control`, `csrf`, `input_validation`, `rate_limit`, `cors`, `info_disclosure`. See `ATTACT/checks/` for each module.

## Usage

```
python -m ATTACT --list-checks
python -m ATTACT --target http://127.0.0.1:8000 --confirm-authorized
python -m ATTACT --target http://127.0.0.1:8000 --confirm-authorized --checks security_headers,cookie_security,cors
python -m ATTACT --target http://127.0.0.1:8000 --confirm-authorized --auth-user u --auth-pass p --access-user-a admin --access-pass-a x --access-user-b bob --access-pass-b y
python -m ATTACT --target http://127.0.0.1:8000 --confirm-authorized --timeout 4 --max-requests 60 --json-out attact-report.json
python -m ATTACT --target http://10.0.0.5:8000 --allowlist 10.0.0.5 --confirm-authorized
```

Prints a terminal summary and, with `--json-out`, writes JSON with `target, timestamp, checks, allowlist, request_count, elapsed_ms, limitations, findings[]` (`check, title, status, severity, confidence, summary, evidence, remediation`).

Statuses: `confirmed` (unambiguous, e.g. `/.env` 200), `potential` (needs manual verification), `not_found`, `not_run`. No confirmed from a single status/keyword.

## Demo

```
run.bat start
python -m ATTACT --target http://127.0.0.1:8000 --confirm-authorized --checks security_headers,info_disclosure --json-out attact-demo.json
```

Sample JSON (simulated, abbreviated):

```json
{
  "tool": "ATTACT", "version": "0.1.0",
  "target": "http://127.0.0.1:8000",
  "checks": ["security_headers"],
  "findings": [{"check":"security_headers","title":"Header: content-security-policy","status":"not_found","severity":"info","confidence":"high","summary":"Header 'content-security-policy' is present"}]
}
```

## Limitations

No exploitation, chaining, brute force, or DoS. `potential` always needs human confirmation. Not a substitute for manual review / licensed pentest. No stealth/evasion.

## SentientAI adapter (optional)

`ATTACT/adapters/sentient.py` — read-only helper that formats a saved JSON report for display (`load_report` / `findings_for_template`). Never launches scans; wire behind an admin view only.

## Tests

```
python -m pytest tests/test_attact*.py -v
```
