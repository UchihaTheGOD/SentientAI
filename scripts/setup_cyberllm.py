"""Check (and optionally download) the project-local CyberLLM artifacts.

Usage (from the project root, or anywhere — paths resolve from the project):
  python scripts/setup_cyberllm.py --check
  python scripts/setup_cyberllm.py --download-base
  python scripts/setup_cyberllm.py --download-adapter

Safety rules, by design:
- --check never downloads, never overwrites, never needs credentials.
- Downloads never overwrite a file that already validates; HF downloads
  resume via huggingface_hub, Kaggle adapter files are only ~82 MB.
- No credentials are read from, written to, or printed by this script.
  Kaggle auth stays in ~/.kaggle/kaggle.json; HF base is ungated.
- The adapter is verified by SHA-256 after download; a mismatch is fatal.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.services.cyberllm_loader import (  # noqa: E402
    resolve_cyberllm_paths,
    validate_cyberllm_artifacts,
)

ADAPTER_FILES = [
    ("adapter_17b_datav32_adapter_config.json", "adapter_config.json"),
    ("adapter_17b_datav32_adapter_model.safetensors", "adapter_model.safetensors"),
    ("adapter_17b_datav32_chat_template.jinja", "chat_template.jinja"),
    ("adapter_17b_datav32_tokenizer.json", "tokenizer.json"),
    ("adapter_17b_datav32_tokenizer_config.json", "tokenizer_config.json"),
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check() -> int:
    paths = resolve_cyberllm_paths()
    print(f"model root: {paths.root} (source: {paths.source})")
    print(f"base:       {paths.base_dir} ({paths.base_model_id}@{paths.base_revision})")
    print(f"adapter:    {paths.adapter_dir}")
    missing = validate_cyberllm_artifacts(paths)
    if missing:
        print("MISSING / INCOMPLETE:")
        for item in missing:
            print(f"  - {item}")
        print("See cyberLLMv1/README.md for download commands.")
        return 1
    adapter_file = paths.adapter_dir / "adapter_model.safetensors"
    actual = sha256(adapter_file)
    if paths.adapter_sha256 and actual.lower() != paths.adapter_sha256.lower():
        print(f"ADAPTER SHA MISMATCH: got {actual}, expected {paths.adapter_sha256}")
        return 1
    print(f"OK: base + adapter present; adapter SHA-256 matches ({actual[:16]}…).")
    return 0


def download_base() -> int:
    paths = resolve_cyberllm_paths()
    try:
        from huggingface_hub import snapshot_download
    except ImportError:
        print("huggingface_hub is not installed: pip install huggingface_hub")
        return 2
    snapshot_download(
        repo_id=paths.base_model_id,
        revision=paths.base_revision,
        local_dir=str(paths.base_dir),
        local_dir_use_symlinks=False,
    )
    print(f"Base downloaded to {paths.base_dir}")
    return check()


def download_adapter() -> int:
    paths = resolve_cyberllm_paths()
    paths.adapter_dir.mkdir(parents=True, exist_ok=True)
    for kaggle_name, canonical in ADAPTER_FILES:
        target = paths.adapter_dir / canonical
        if target.is_file():
            print(f"skip (already present): {canonical}")
            continue
        result = subprocess.run(
            [
                "kaggle", "datasets", "download",
                "-d", "uchihamadarum/cyber-llm-artifacts",
                "-f", kaggle_name, "-p", str(paths.adapter_dir),
            ],
            check=False,
        )
        if result.returncode != 0:
            print(f"kaggle download failed for {kaggle_name} (exit {result.returncode})")
            return result.returncode
        downloaded = paths.adapter_dir / kaggle_name
        if downloaded.is_file() and downloaded != target:
            downloaded.rename(target)
    print(f"Adapter downloaded to {paths.adapter_dir}")
    return check()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--download-base", action="store_true")
    group.add_argument("--download-adapter", action="store_true")
    args = parser.parse_args(argv)
    if args.check:
        return check()
    if args.download_base:
        return download_base()
    return download_adapter()


if __name__ == "__main__":
    raise SystemExit(main())
