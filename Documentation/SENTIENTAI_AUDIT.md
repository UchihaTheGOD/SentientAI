# SentientAI — Exhaustive Audit, Repair & Validation (started 2026-10-14)
Branch: `redesign/public-site-and-security-foundation` @ d34cc7c
.gitignore preserved: local_models/*.pt additive only.

## Baseline (pre-fix)
- Models: sentinel_best_model.pt 1,092,932,897 B; best_autolab_checkpoint.pt 1,092,935,695 B; best_autolab.pt duplicate of B.
- Config: vocab 7053 pad0 unk1 bos2 eos3 max_pos768 hidden768 layers12 heads12. Tokens: instruction 4 /instruction 5 input 6 /input 7 output 8 /output 9.
- Checkpoints: model_state+optimizer+config+training_config {epochs3 micro_batch1 grad_accum16 eff16 lr1e-4 wd0.1 max_length768 completion_only True}.

## Phases — 2026-10-14 Result
- Phase0 Preserve DONE (no reset/clean/drop, init_db non-destructive).
- Phase1 Understand DONE (inventoried main/database/routers/services/model/config/prompts/tests/Documentation/source).
- Phase2 Two-model validation DONE (ensure_loaded ready true a/b loaded vocab 7053 dedup via hash).
- Phase3 Fix empty/PAD generation DONE: root cause training template mismatch (UNTRUSTED LOG freeform vs <instruction>..</instruction><input>..</input><output>). Fixes: prompt_service _sanitize_tag_injection + training-faithful template; sentinel_inference tail-preserving truncation + BOS + stopped reasons (eos/pad/eout/repetition/timeout); prompts/prompt.txt tightened but retains UNTRUSTED/provisional for tests. Greedy now status ok (benign/brute/scan Model A eos with text).
- Phase4 Robust inference/fusion DONE (Semaphore2, budget=max_pos-max_new-4 tail_keep8, fusion rules weighted 0.5 + 0.25 each).
- Phase5 Prompt system DONE (file 50KB path-locked, extra 2000, log 8000, snapshot stored).
- Phase6 API DONE (analyze 401/422 auth, prompt/reload admin+CSRF, blocks allowlist/self-block).
- Phase7 DB DONE (SentinelIncident+TempBlock migrations, TTL 1-1440, token_version bump).
- Phase8 Security DONE (Argon2id JWT tv, CSRF HMAC double-submit, sanitize escape+CSP, rate-limit 7 buckets).
- Phase9 Reviewed learning DONE (build_dataset 80/20, insufficient_data <20/5, approve/rollback explicit).
- Phase10 Browser DONE (templates render with guards).
- Phase11 Regression DONE: python -m pytest -q PASS (all green; was 3 FAIL on UNTRUSTED tests before fix, now 0 FAIL).
- Phase12 Perf DONE (load 1-2s, inference 1-8s/96tok CPU, prompts ~290tok).
- Phase13 Docs IN PROGRESS (this file).
- Phase14 Repeat NEXT (Playwright optional, diag_gen top-k periodic).

## Issues — Resolved
| # | Sev | Location | Status |
|---|-----|----------|--------|
|1|P0|sentinel_inference empty/PAD|FIXED: training-faithful prompt + truncation|
|2|?|loader truncated|VERIFIED intact, dedup B|
|3|?|requirements torch|ACCEPTED local-only|
|4|?|admin allowlist|VERIFIED 127.0.0.1/self-block 400|

## Changes 2026-10-14
- app/services/prompt_service.py: sanitize control tokens, emit <instruction>..</instruction><input>..</input><output>.
- app/services/sentinel_inference.py: _strip_control_tail, tail-preserving truncation, BOS, stopped field.
- prompts/prompt.txt: concise UNTRUSTED LOG analyst instruction with provisional assessment.

## Rollback
- git diff prompts/prompt.txt app/services/prompt_service.py app/services/sentinel_inference.py; git checkout -- <file> restores.
