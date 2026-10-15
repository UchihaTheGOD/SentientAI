# Sentinel Detection Report — Evidence-Based Assessment (2026-10-15)

> Scope: FastAPI app `SentientAI` — Sentinel dual-checkpoint + ATTACT 12-checks + security_events middleware + rate-limit + incident pipeline.
> Principle: honest uncertainty (`confirmed / potential / not_found / not_tested / error`), redacted evidence, monitor-only enforcement.

## 1. Summary

Sentinel today is a **narrow but honest** detection stack: 3 input probes + 3 log-signal rules + 7 infra/header checks actually run and log. Everything else is honest `not_run` / `not_tested`. Models A/B **load and generate** (vocab 7053, hidden 768, 12 layers, max_pos 768) but contribute only a **weak keyword vote** to fusion (0.25 each, same family, not independent); the **working** detection is rule-based. No category beyond the table in section 2 has been shown to meet precision/recall targets — the repo has no `evaluation_matrix.py`.

## 2. Which Categories Have Working Detection

| Layer | Category | How it detects (code) | Status | Evidence cap |
|-------|----------|------------------------|--------|--------------|
| Web/input | **Reflected XSS** | `security_events._is_xss_probe` contextual (tag+handler, not bare word) + middleware dedup per correlation_id; ATTACT `checks/xss.py` canary `ATTACT-XSS-CANARY-9f3a1b` reflection+encoding check | **Working (monitor-only)** | evidence [:2000], meta query_len |
| Web/input | **SQLi probe** | `_is_sqli_probe` requires keyword + operator/quote pattern; ATTACT `checks/sqli.py` single-quote probe + SQL error patterns + 5xx flip | **Working (monitor-only)** | 600 char body snippet |
| Web/input | **Path traversal** | `_is_traversal_probe` requires `../`/`%2e%2e` + `etc/passwd`/`win.ini`/`canary`; middleware + ATTACT `path_traversal.py` | **Working** | path/query 500 |
| Auth/abuse | **Brute-force / credential stuffing** | `auth.py` logs `auth.login_failed` (400) + `auth.brute_force` high after >=5/10m per IP (window dedup); `fusion.evaluate_rules` counts `failed` lines >=5 | **Working** | ip_hash, window dedup |
| Auth/abuse | **Rate/abuse** | `ratelimit.py` in-process sliding window (`limit_login 30/300s`, 7 buckets); ATTACT `rate_limit.py` low-rate 429/header check | **Working, single-process only** | Retry-After |
| Auth/abuse | **Port scan / probing** | `fusion._port_scan_indicators` >=8 distinct ports or keyword `nmap` | **Working (log-text only)** | ports list 12 |
| Auth/abuse | **Success-after-fail** | `fusion._success_after_fail` | **Working** | +25 score |
| Infra | **Security headers** | `checks/security_headers.py` reads GET / headers | **Working** | header dump 80 |
| Infra | **Cookie security** | `checks/cookie_security.py` parses Set-Cookie attrs | **Working** | attrs_lower |
| Infra | **CORS** | `checks/cors.py` | **Working** | origin reflection |
| Infra | **Info disclosure** | `checks/info_disclosure.py` `has_stack_trace` | **Working** | 4000 cap |
| Infra | **CSRF** | `checks/csrf.py` token+cookie + POST-without-token probe | **Working (best-effort)** | 500 |
| Infra | **Input validation / method** | `checks/input_validation.py` OPTIONS + malformed JSON + 2000-char param 5xx | **Working** | status only |
| Platform | **Access log 401/403/429** | `middleware` logs `http.401/403/429` (skip /static) | **Working** | duration_ms |
| Platform | **Incident correlation** | `incident_service.py` dedup 10m by ip+prompt hash, timeline | **Working, per-request only** | pseudonymous ip_hash |

No working detection today for: **CMDi, SSRF, SSTI, deserialization, HTTP smuggling, file-upload bypass, open redirect, host-header poisoning, second-order / DOM XSS, full SSTI code audit, IDOR beyond two-account comparison**. Those are required by broad coverage but have no detector module.

## 3. Rules vs. Actual Language Models

| Category | Primary decision maker | Model role | Why |
|----------|------------------------|------------|-----|
| XSS / SQLi / traversal (HTTP probe) | **Rules** (`_is_*_probe` + ATTACT) | None | Regex + context; LMs not invoked on HTTP path |
| Brute-force / scan / success-after-fail (log) | **Rules** `evaluate_rules` | **Weak vote** `fuse()` adds model_a/b 0.25 (0.12 if not ok), rules 0.5 | Models trained `completion_only True` on free-form prose — not per-category labels |
| Headers / cookie / CORS / CSRF / info disclosure | **Rules** | None | Static analysis |
| Auth_session / access_control | **Honest `not_run`** | None | Needs test accounts |

**Model reality:** config vocab 7053 hidden 768 12x12 max_pos 768 pad0/unk1/bos2/eos3 specials `<instruction>` 4 .. `</output>` 9, `completion_only True`, val_loss 0.101 on `best_autolab_checkpoint.pt` 1.09 GB; `sentinel_best_model.pt` 1.09 GB, `best_autolab.pt` duplicate of B (hash dedup). Loader `ensure_loaded()` tail-preserving truncation (budget max_pos-max_new-4, keep 8 tail incl `</output>`). Inference CPU greedy semaphore 2, MAX_NEW 256, timeout 12s, `_strip_control_tail`. Fusion parses by substring — fragile, no JSON schema. Pre-fix: Model A garbled 8-21 tok, Model B empty 5 tok, `parse null`. Post-fix restored `status ok` but no per-category precision/recall. **No retrain per spec; claiming AI detects SQLi would be fabrication.** Fused verdict is 50% rules; agreement is correlation not confirmation.

## 4. Which Categories Have Been Empirically Evaluated

| Harness | What was measured | Result |
|---------|-------------------|--------|
| `tests/test_sentinel_phase1.py` (5 tests) | loader dual-load/dedup, logits shape, dual inference structure, evaluate_rules deterministic, incidents+TempBlock lifecycle, training_pipeline 80/20 | **PASS** (6 passed with attact) |
| `tests/test_attact_checks.py` + scope | 6 infra checks + XSS/SQLi/traversal canary + scope | PASS (12 passed aggregate) |
| `verify_strict_final.py` / `run_strict.py` + `run_strict2.py` live | failed/brute/xss/sqli/traversal/benign/authz/filters/redaction/admin/attact(23/29/12/12)/sentinel(vocab 7053) | **PASS** then cleaned |
| `test_prompt_and_readiness`, `test_sentinel_api` | prompt file + provisional labels, API 401/422 | PASS (was 3 FAIL before Phase 3 fix) |
| **Not evaluated** | Per-category precision/recall/F1 (benign/suspicious/attack/auth-abuse/malformed); CMDi/SSRF/SSTI/deser/smuggling/upload/open-redirect; behavioral window; JSON-schema accuracy | **No matrix exists** |

Latency: load 1-2s, inference 1-8s/96 tok CPU, prompts ~290 tok. DB persistence asserted: `security_events ~334, attact_assessments 23, findings 286` (prior run).

## 5. False-Positive and False-Negative Results

### False positives

| Probe | Expected | Observed |
|-------|----------|----------|
| `SELECTION committee report` (benign word containing `select`) | likely_benign | **likely_benign (0)** — `_is_sqli_probe` requires `select` + operator/quote |
| `User alice viewed post /blog/hello-world 200` | likely_benign | likely_benign |
| `etc/passwd` without `../` | likely_benign | likely_benign (traversal requires dots) |

No FP in benign probes with contextual guards. Residual FP risk: `nmap` keyword alone flags port_scan (intended needs_review, may FP on docs).

### False negatives

| Probe | Expected | Observed | Root cause |
|-------|----------|----------|------------|
| 6 failed logins joined by **spaces** (single line) | likely_threat | **likely_benign (failed_count=1)** — `_count_failed_logins` splits by `splitlines()` | FN if aggregator joins lines |
| Same 6 failures joined by **newlines** | likely_threat | score 40 needs_review | Works as lines — brittle |
| CMDi `; cat /etc/passwd`, SSRF `169.254.169.254`, SSTI `{{7*7}}` | flagged | **Not detected** | Missing modules |
| DOM XSS, stored XSS second-order, full SSTI, deser gadget | not_tested | not_tested | HTTP-only cannot prove |

FN risk > FP risk. Complete FN for 8 missing web categories.

## 6. What the Current Models Cannot Reliably Detect

1. Per-category threat beyond generic prose — no signal for CMDi/SSRF/SSTI/deser/smuggling/upload/open-redirect.
2. Structured multi-class output — no JSON schema; substring parsing lossy; empty/PAD/repetition observed.
3. Long context — max_pos 768 truncates multi-hour sequences.
4. Independent corroboration — A and B same family; agreement not independent.
5. Categories needing external instrumentation: DOM XSS (browser), SSTI (template audit), deser (object graph), SSRF (DNS/egress), smuggling (HTTP raw), upload (magic), IDOR (two-account).
6. Prompt-injected logs — `_sanitize_tag_injection` brackets tags, but no robustness eval.

## 7. What Data, Training, or Instrumentation Is Needed Next

**Data:** `training_examples` with category (xss/sqli/traversal/cmdi/ssrf/ssti/deser/smuggling/upload/open_redirect/auth_abuse/infra/benign), ground_truth (benign/suspicious/attack), evidence, provenance, safe_to_train, status candidate->approved->trained. Need 80/20 stratified per category (pipeline `insufficient_data` if <20 train or <5 eval). Include benign/suspicious-safe pairs (`SELECTION` vs `SELECT * WHERE id='1' OR '1'='1'`), malformed, encoding variants (`%3Cscript`, double-encoding), multiline vs single-line brute-force. Hash IPs, pseudonymous session digests, prompt snapshot per incident.

**Training:** Fine-tune with structured JSON `{verdict, category, severity, confidence, evidence[], uncertainty, limitations[]}` validated by schema; completion_only but emit JSON after `<output>`. Evaluate per-category precision/recall/F1 and ECE, not just val_loss 0.101. Rejection learning via `incident_service.update_review` -> pipeline; keep AI queue separate from reviewed queue. If data insufficient keep models advisory (rules 0.6).

**Instrumentation:** `app/services/detectors/` (signatures, web, auth, abuse, infra) + `behavioral_store.py` DB sliding window (ip_hash/session_digest/user_id/route 10m/1h). Extend `security_events._is_*_probe` + middleware for 8 missing categories (bounded evidence 2000, redacted, per-correlation_id dedup), log 5xx and unexpected methods. Redis rate limit if multi-process (today `_HITS` resets on restart). Build `evaluation_matrix.py` + `docs/EVALUATION.md` matrix (benign/suspicious/attack/auth-abuse/malformed, ground truth, detectors, Model A/B raw+parsed, fusion, latency/errors, precision/recall/F1).

**Enforcement:** Monitor-only default; high-confidence blocks only via `incident_service.apply_temp_block` TTL 1-1440 with expiry/unblock/revocation/audit; never block on model-only signal.

## 8. How to Verify

```powershell
python -m pytest tests/test_sentinel_phase1.py tests/test_attact_checks.py -q
# Expected: 12 passed
python -c "from app.services.sentinel_fusion import evaluate_rules; print(evaluate_rules(chr(10).join(['2024-01-01 10:00:00 WARN 192.168.1.10 login failed 401']*6)))"
# Expected: failed_count 6, score 40
```

Strict harness when recreated: `Remove-Item verify_strict_final.py` after run; assert `security_events ~334, attact_assessments 23, findings 286`.

## 9. Limitations

Code audit + bounded probes, not a full red-team. `confirmed` requires manual verification; `potential` is not proof. Any future AI claim must cite per-category evaluation matrix.


