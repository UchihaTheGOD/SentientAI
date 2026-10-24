# SECURITY FINDINGS — SentientAI (2026-10-20 retry)

> Controlled local assessment only (`http://127.0.0.1:8000`). Synthetic inputs. No external targets, no destructive payloads. Retry scope — small/factual.

## Confirmed

| ID | Severity | Component | Observation | Evidence | Status |
|---|---|---|---|---|---|
| — | — | — | No confirmed vulnerability in this retry scope (CSRF, admin gates, headers, SSRF allowlist all behaved as expected) | `logs/security_retry.log` | N/A |

## Potential (requires follow-up, not confirmed exploit)

| ID | Severity | Component | Observation | Why not confirmed | Next check |
|---|---|---|---|---|---|
| P-01 | Low | CSP | `script-src 'self' 'unsafe-inline'` weakens CSP XSS layer | `sanitize.py` escapes all user HTML before rendering — no bypass proven | Verify no `| safe` on user content; keep `unsafe-inline` only if needed |
| P-02 | Low | Rate limit | In-process `dict+deque` (no Redis) — per-process only | Sufficient for single-process SQLite app; not tested under multi-worker | Load-test or document single-process assumption |

## Informational (verified in this run)

| ID | Component | Observation | Evidence |
|---|---|---|---|
| I-01 | Headers/CSP | All security headers present on `/api/health` and `/` (`nosniff`, `DENY`, CSP, `strict-origin-when-cross-origin`, `Permissions-Policy`, `X-XSS-Protection`) | `logs/security_retry.log` §1 |
| I-02 | CSRF/Admin/SSRF | CSRF double-submit enforced (POST without token → 403; with valid token → 400 not 403); `/admin` and `/admin/security` anon → 303 `/login?next=`; `validate_target_url` allows only `127.0.0.1/localhost/::1/testserver` + local origin + `SECURITY_LAB_ALLOWLIST`, blocks credentials/private hosts | `logs/security_retry.log` §2-3; `app/services/security_lab.py:validate_target_url` |

> No secrets recorded. Synthetic inputs only.
