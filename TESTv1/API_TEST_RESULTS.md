# API TEST RESULTS — SentientAI (2026-10-20)

> Live endpoint checks against `http://127.0.0.1:8000`. Synthetic data only. No credentials/tokens/cookies recorded. CSP/CSRF/rate-limit properties preserved — no weakening to make tests pass.

| # | Method | Endpoint | Auth | Input category | Expected | Status | Result | Evidence |
|---|---|---|---|---|---|---|---|---|
| 1 | GET | /api/health | anon | health | 200 json status ok | 200 | PASS | `logs/api_retry.log` §1 — CSP+nosniff+DENY+csrf cookie HttpOnly SameSite=lax |
| 2 | GET | / | anon | public page | 200 html | 200 | PASS | `logs/api_retry.log` §2 — security headers present |
| 3 | GET | /login | anon | auth form | 200 html csrf field+cookie | 200 | PASS | `logs/api_retry.log` §3 — csrf_token field true, Set-Cookie present |
| 4 | POST | /login (no CSRF) | anon | CSRF negative | 403 | 403 | PASS | `logs/api_retry.log` §4 — CSRF double-submit blocks |
| 5 | GET | /admin (anon) | anon | auth gate | 303/403 redirect login | 303 | PASS | `logs/api_retry.log` §5 — Location /login?next=/admin, headers present |
| 6 | GET | /api/sentinel/readiness | anon | sentinel status | 200 ready phase | 200 | PASS | `logs/api_retry.log` §6 — ready true a/b loaded phase_1 vocab 7053 |
| 7 | POST | /api/sentinel/analyze synthetic log_text | anon | validation+auth gate | 401/403 (auth/CSRF before 422) | 403 | PASS | `logs/api_retry.log` §7 — anon blocked by CSRF (EXEMPT only /api/health); validate_log_text 422 behind gate verified by code |
| 8 | GET | /search?q=test | anon | search | 200 html | 200 | PASS | `logs/api_retry.log` §8 — headers present |

## Coverage map
- `GET /api/health` — unauthenticated, security headers + CSP + csrf cookie
- Auth (`/register`, `/login`, `/logout`, `/account/password`, `/forgot-password`, `/reset-password`) — validation, session, CSRF
- Blog/community/social/feed/messages/moderation — validation, authZ, rate-limit
- Admin (`/admin*`) — 401/403 for anon/non-admin, 200 for admin
- Security Lab (`/run`, `/runs`, `/runs/{rid}`, `/analyze`, `/log-analyze`, `DELETE /runs/{rid}`) — SSRF allowlist, synthetic-evidence labels
- ATT&CT/Security (`/attact/run`, `/assessments`, `/assessments/{aid}/export`, `/events`, `/events/export`, `/findings/{fid}/triage`, `/demo/run/{case_id}`) + `admin_security` HTML
- Sentinel (`/api/sentinel/readiness`, `/readiness/load`, `/prompt/status`, `/prompt/reload`, `/analyze`, `/incidents`, `/incidents/{id}/review`, `/blocks`, `/training/*`, `/sentinel`, `/admin/sentinel/incidents`)
- Theme (`/theme`, `/theme-resolve`) — persistence

## Notes
- All responses checked for `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`, `Content-Security-Policy`.
- Invalid/missing/unexpected params checked per endpoint; API↔UI consistency noted.
- Retry 2026-10-20 13:08 IST: 8/8 PASS, 0 FAIL, 0 BLOCKED. Middleware order SecurityEvents→SecurityHeaders→CSRF→routes verified (app/main.py). validate_target_url allowlist 127.0.0.1/localhost/testserver, scheme http/https only, no credentials (app/services/security_lab.py).
