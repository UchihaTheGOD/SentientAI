# CyberLLM model artifacts — project-local layout

Full setup, Windows commands, and the continuous-learning workflow are
in `CYBERLLM_PORTABLE_SETUP.md` at the project root and in
`reports/full_validation_report.md`.

This directory is the **default** CyberLLM location. The loader derives it
from the project root (`<project>/cyberLLMv1`), not from the shell's current
directory and not from any personal folder. Move or clone the project and
this layout moves with it.

## Layout

```text
cyberLLMv1/
  base/          # Qwen/Qwen3-1.7B at the pinned revision in manifest.json
    config.json, generation_config.json
    model-00001-of-00002.safetensors, model-00002-of-00002.safetensors
    model.safetensors.index.json
    tokenizer.json, tokenizer_config.json, vocab.json, merges.txt
  adapter/       # Pilot v8 LoRA adapter (NOT a merged model)
    adapter_config.json, adapter_model.safetensors
    chat_template.jinja, tokenizer.json, tokenizer_config.json
  manifest.json  # Tracked in Git: model id, pinned revision, adapter SHA-256
  README.md      # This file, tracked in Git
```

Weights (`*.safetensors`, `*.bin`, `*.pt`) are **never committed** — see
`.gitignore`. Only `manifest.json` and this README are tracked from this
directory.

## Downloads (about 4.2 GB total; do not run blindly)

Base, about 4.1 GB, Apache-2.0, ungated, pinned revision — do not use `main`:

```powershell
pip install huggingface_hub
huggingface-cli download Qwen/Qwen3-1.7B `
  --revision 70d244cc86ccca08cf5af4e1e306ecf908b1ad5e `
  --local-dir cyberLLMv1/base --local-dir-use-symlinks False
```

Adapter, about 82 MB, from the private Kaggle dataset
`uchihamadarum/cyber-llm-artifacts` (version 14). Only the six
`adapter_17b_datav32_*` files are pilot v8 — do **not** pick
`adapter_17b_datav2_*` (pilot v4) or `adapter_datav2_*` (pilot v3):

```powershell
pip install kaggle
# kaggle.json belongs in $env:USERPROFILE\.kaggle\kaggle.json — never commit it.
kaggle datasets download -d uchihamadarum/cyber-llm-artifacts -f adapter_17b_datav32_adapter_config.json   -p cyberLLMv1/adapter
kaggle datasets download -d uchihamadarum/cyber-llm-artifacts -f adapter_17b_datav32_adapter_model.safetensors -p cyberLLMv1/adapter
kaggle datasets download -d uchihamadarum/cyber-llm-artifacts -f adapter_17b_datav32_chat_template.jinja    -p cyberLLMv1/adapter
kaggle datasets download -d uchihamadarum/cyber-llm-artifacts -f adapter_17b_datav32_tokenizer.json         -p cyberLLMv1/adapter
kaggle datasets download -d uchihamadarum/cyber-llm-artifacts -f adapter_17b_datav32_tokenizer_config.json  -p cyberLLMv1/adapter
# Then rename to the canonical names the loader expects:
Rename-Item cyberLLMv1/adapter/adapter_17b_datav32_adapter_config.json   adapter_config.json
Rename-Item cyberLLMv1/adapter/adapter_17b_datav32_adapter_model.safetensors adapter_model.safetensors
Rename-Item cyberLLMv1/adapter/adapter_17b_datav32_chat_template.jinja    chat_template.jinja
Rename-Item cyberLLMv1/adapter/adapter_17b_datav32_tokenizer.json         tokenizer.json
Rename-Item cyberLLMv1/adapter/adapter_17b_datav32_tokenizer_config.json  tokenizer_config.json
```

Or run the checker (no downloads, no overwrites):

```powershell
python scripts/setup_cyberllm.py --check
```

Verify the adapter hash (the loader also refuses a mismatch):

```powershell
(Get-FileHash cyberLLMv1/adapter/adapter_model.safetensors -Algorithm SHA256).Hash
# must equal: D624ED793A45A64CB541577441C87C7D2FEB83C37A84DA057D1C15E58E45A5B1
```

## Overrides and migration

- `CYBERLLM_MODEL_ROOT` — point at a different model root (relative paths
  resolve against the project root, not the cwd). When this is set, an
  incomplete root is a hard error; the loader will not silently download.
- `CYBERLLM_BASE_DIR` / `CYBERLLM_ADAPTER_DIR` — legacy per-directory
  overrides, kept for compatibility.
- Migrating from an old layout: **copy, do not move**, your existing base
  and adapter into `cyberLLMv1/base` and `cyberLLMv1/adapter`, run
  `python scripts/setup_cyberllm.py --check`, and only then consider
  removing the old copy. The old `local_models/cyberllm/v8` adapter is
  still used as a fallback when `cyberLLMv1/adapter` is absent.
- GPU: Qwen3-1.7B in float16 is about 3.4 GB of weights, about 4.5 GB peak
  with CUDA context/KV/activations — tight but workable on a 6 GB GTX 1660.
  `CYBERLLM_DEVICE=auto` (default), `cpu`, or `cuda`;
  `CYBERLLM_LOAD_IN_8BIT=1` is the bitsandbytes fallback on CUDA.
  On CPU, expect slow inference (minutes per request on a 2-CPU VM in
  earlier testing) — that is a hardware limit, not a bug to hide.
