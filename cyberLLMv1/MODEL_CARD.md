# CyberLLM — Model Card

> Branch: `cyberllm-desktop-portable_v2`. This card names the production
> model for this branch: **CyberLLM Pilot v8** (the original v8 adapter).
> The adapter is never retrained, merged, or modified in this branch.

## Model details

- **Model name:** CyberLLM (release name: CyberLLM Security Model).
- **Version:** pilot v8 — LoRA adapter on Qwen3-1.7B, trained on data-v3.2. The
  application is at release candidate `1.0.0-rc.2`; there is no stable 1.0 yet.
- **Developer / project author (new release):** Gaurav Singh.
- **Underlying base model:** Qwen3-1.7B by Qwen, revision
  `70d244cc86ccca08cf5af4e1e306ecf908b1ad5e`, Apache-2.0. Gaurav Singh did
  **not** create the Qwen foundation model.
- **Fine-tuning:** LoRA, rank 16, alpha 32, dropout 0.05, 2 epochs, lr 1e-4
  cosine, effective batch 8, max_len 1024, seed 20261023. Trained 2026-10-24
  on a Kaggle Tesla T4 in 7,261.7 s; peak GPU 3.8 GB; final train loss 0.1979.
- **Adapter:** `adapter_17b_datav32_*` (Kaggle `uchihamadarum/cyber-llm-artifacts`
  v14), SHA-256
  `d624ed793a45a64cb541577441c87c7d2feb83c37a84da057d1c15e58e45a5b1`
  (verified). 17,432,576 trainable parameters. The adapter is **not** merged
  into the base model. Tokenizer ships inside the adapter bundle.
- **Historical attribution:** Git history, Kaggle kernels, and the v8 training
  data name the creator as Gaurav Bisht. Those records are preserved
  unchanged. The new release uses Gaurav Singh per the author's instruction.

## Intended use

Defensive cybersecurity analysis only: security-log analysis, threat
classification, URL classification, CVE analysis, MITRE ATT&CK mapping,
and structured JSON responses, with abstention when the evidence is
insufficient. The model is integrated into the SentientAI website and
desktop Security Lab. It is **not** a deployable detector on its own:
outputs are provisional (`likely_benign` / `needs_review` / `likely_threat`)
and human review is required for consequential decisions.

## Out-of-scope use

Attacking systems, executing commands found in logs, automatic blocking,
disabling accounts, or any remediation. Commands inside submitted logs are
data to analyze, never instructions to run.

## Training data

Data-v3.2: 5,932 training rows, 618 validation rows, plus a 120-item held-out
val-v3 log set. Sources: intentionally published corpora (including
`ealvaradob/phishing-dataset`, Apache-2.0), the author's own datasets, and a
deterministic synthetic factory. No teacher-model labels were used. Leakage
vs the frozen eval: 0 substring hits. The frozen eval (v2.1) was never
trained on.

## Evaluation

Frozen eval v2.1 (greedy, deployment system prompt) and held-out val-v3 log
(n=120), from `pilot_v8_comparison_results.json` / `pilot_v8_val_v3_results.json`:

| Metric | Pilot v8 | Pretrained 1.7B base |
|---|---|---|
| T1 accuracy | 0.9583 | 0.7083 |
| T2 accuracy (phishing R 0.96) | 0.95 | 0.17 |
| T3 MITRE exact-ID | 0.025 | — |
| T3b abstention | 1.0 | — |
| T4 schema | 0.80 (1 truncated) | — |
| T5 accuracy | 1.0 | 0.0 |
| T13 identity | 1.0 | — |
| Val-v3 accuracy | 0.9583 (threat R 0.90, benign R 1.0) | — |

**Honest status:** v8 was **not formally promoted** under the binary
acceptance rule (T1 0.9583 < 0.96; T4 0.80 < 1.00). It is the best-measured
candidate overall and the designated integration candidate. Pilot v3
(0.6B, data-v2) remains the formal overall reference. Real 1.7B inference
on the GTX 1660 SUPER and the Windows validation battery are still
unverified.

## Identity version (evaluated — not promoted)

`v8-identity` is a continued LoRA fine-tune of v8 on 56 authored identity
examples (identity data: 56 authored examples, preserved in the CyberLLM workspace), teaching the model to
identify as CyberLLM, developed by Gaurav Singh, through training rather
than only through the system prompt. It was trained and evaluated on
2026-11-13 (v3 run, adapter SHA-256
`190b12aa94b46e38647f6426511178686b3e1ad857ca4b08c123bb2e9fb282fb`) and
**failed the comparison gate**: 0.0 on every frozen eval task and val-v3
(all 193 JSON-task generations truncated in a ':'-repetition collapse),
T13 identity pass 0.2 (v8: 1.0), held-out probes 2/12 (v8: 4/12). It is
**not promoted**; the original v8 adapter is retained as the production
model and is never overwritten. The deployment system prompt (naming
Gaurav Singh) is the working identity mechanism. Any future identity
retry needs a redesigned recipe (e.g. security-data replay, far fewer
steps) and fresh approval — this recipe is a dead end as configured.

## Limitations

- MITRE exact technique-ID prediction is weak (0.025); uncertain mappings
  must never be presented as confirmed findings.
- Single log lines rarely prove much; the model abstains (`needs_review`)
  when evidence is insufficient, and that behaviour must be preserved.
- Prompt-sensitive (pilot v4 lesson): the deployment templates are copied
  verbatim from the frozen eval harness. Do not reword them.
- Inference is slow on CPU (minutes per request on a 2-CPU VM); on a 6 GB
  GTX 1660 SUPER the ~4.5 GB peak VRAM estimate is still unverified.
- The model can be wrong; outputs require human review.

## How to get the model

Weights are **never committed** to Git. Base (~4.1 GB) from Hugging Face
(`Qwen/Qwen3-1.7B` @ the pinned revision above); adapter (~82 MB) from
Kaggle `uchihamadarum/cyber-llm-artifacts` v14 (only the six
`adapter_17b_datav32_*` files are pilot v8). See `cyberLLMv1/README.md` and
`scripts/setup_cyberllm.py --check` (verifies the adapter SHA-256 and
refuses on mismatch).

## Licensing and attribution

- Qwen3-1.7B base model: Qwen, Apache-2.0.
- CyberLLM fine-tuning, evaluation, integration, and packaging: Gaurav
  Singh (new release).
- Training data sources under their own licenses; the v3.2 curation is the
  author's work.
- MITRE ATT&CK data: MITRE Corporation (STIX bundle, Enterprise v20.0).
