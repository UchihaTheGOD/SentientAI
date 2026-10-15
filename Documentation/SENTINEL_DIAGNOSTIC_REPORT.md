# Sentinel Diagnostic Report — Reproducible Failure Analysis (2026-10-15)

Scope: local checkpoints `local_models/sentinel/sentinel_best_model.pt` (1092932897 B, epoch 3) + `best_autolab_checkpoint.pt` (1092935695 B, epoch 1), vocab 7053, config pad0 unk1 bos2 eos3, max_pos 768, hidden 768 layers 12. No retraining performed.

## 1. Loader and tokenizer — PASS

- `sentinel_loader.ensure_loaded()` returns `ready True`, `a loaded`, `b loaded`, vocab 7053, load_ms ~1.1-1.3s, RSS ~1960 MB. Both checkpoints contain `model_state_dict` (149 keys), `config` matching `SentinelConfig`, `training_config {completion_only True, max_length 768}`.
- `sentinel_tokenizer.json` vocab 7053; special tokens map correctly: pad0 `<pad>`, unk1 `<unk>`, bos2 `<bos>`, eos3 `<eos>`, `<instruction>`4 `</instruction>`5 `<input>`6 `</input>`7 `<output>`8 `</output>`9. Byte-fallback `Ġ` (U+0120) renders as `─á` on cp1252 console — not a model error.

## 2. Prompt template — VERIFIED training-faithful, not root cause of emptiness

- `prompt_service.build_analysis_prompt` emits `<instruction>{base}</instruction><input>{sanitized_log}</input><output>` with `_sanitize_tag_injection` bracketing control tokens. This matches `completion_only` training (model learns to generate after final `<output>`). Verified tail-preserving truncation keeps `<output>` at ids tail: prompt length ~319 tokens for benign case, last ids `[19,21,...,7,8]` where 7=`</input>` 8=`<output>`. BOS prepended at inference; budget `max_pos-max_new-4`.

## 3. Generation — EVIDENCE OF FAILURE (no assumption)

Reproducible probe (`check_infer_detail.py`, `max_new_tokens 64`, timeout 15s, greedy decode):

- Model A (sentinel_best_model.pt): status `ok` but text `"─ámedium - based ─áaccess ─áto ─áthis ─áweek ."` tokens 8 stopped `eos`. For 26-case set: 24 empty / 2 garbage FP. Top-k logits at first step on benign prompt: top 1744 (`─ádoes` 5.33), 1251 (`─ádistinct` 4.76), ... eos logit 1.53 low but not dominant. Generation is short, repetitive, non-schema.
- Model B (best_autolab_checkpoint.pt): status `empty` tokens 5 stopped `repetition`, text `""`. For 26 cases: 26/26 empty. Top-k at same prompt: unk 7.27, `":` 5.8, `─á"` 5.45 — degenerate: predicts `<unk>` strongly. eos logit 4.01 high → immediate termination and repetition guard triggers empty.

Decoded token IDs before cleanup were recorded via `_generate_for_model` raw `gen_ids`; after `_strip_control_tail` still empty/garbage. EOS/PAD handling terminates correctly; repetition guard explains B empty.

## 4. Completion-only labels and data — INSUFFICIENT

- Checkpoints report `best_val_loss 0.101` (A) / `0.075` (B) on private val set, but no structured JSON supervision. Training data never contained 26-case categories (xss/sqli/traversal only in rules). Stored `output` sequences were free-form analyst prose, not validated `{label,category,confidence,evidence,uncertainty,reasoning_summary}` JSON. Hence greedy decode cannot emit valid JSON.

## 5. Existing 26-case evaluation — RAW OUTPUTS

`evaluation/latest.json` (rules only baseline) + `evaluation/results_*_with_models` when probed with both models: Model A 24 empty + 2 garbage, Model B 26 empty, `invalid_json` 26/26, `valid-output rate 0%`, fusion == rules. See `Documentation/EVALUATION.md`.

## 6. Root cause (evidence-supported)

Not tokenizer, not prompt truncation, not EOS decoding. Primary cause: **checkpoints were fine-tuned for free-form analyst prose completion, not for structured moderation JSON; logits favor generic shards (`does`, `distinct`, `<unk>`) over schema keywords. No per-category supervision for benign/suspicious pairs.** Secondary: Model B overfitted to `<unk>`/punctuation, causing immediate repetition/empty.

## 7. Smallest viable next step

Do NOT retrain yet. Fix inference bug already verified (none remaining beyond model quality). Next is **prepare properly labeled fine-tuning dataset**: 80/20 stratified per category (benign, spam, harassment, prompt_injection, ambiguous, attack sub-categories), include benign/suspicious pairs, encoding variants, multiline vs singleline, JSON schema `{label,category,confidence,evidence,uncertainty,reasoning_summary}` validated, completion_only emits after `<output>`, keep eval split isolated from `training_examples`.

Verification: `python check_infer_detail.py 2>&1 | Select-Object -First 150` and `python evaluation_matrix.py --with-models --max-new-tokens 48` reproduce the empty/garbage outputs.
