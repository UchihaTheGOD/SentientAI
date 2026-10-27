"""Portability tests for the project-local cyberLLMv1/ layout.

These tests use a temporary model root, never the real weights, and never
the process working directory: the resolver must derive the default from
the project root (the loader file's location), and a relative override
must resolve against that same root.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from app.services import cyberllm_loader as loader


def _make_root(tmp_path: Path) -> Path:
    base = tmp_path / "base"
    adapter = tmp_path / "adapter"
    base.mkdir(parents=True)
    adapter.mkdir(parents=True)
    (base / "config.json").write_text("{}")
    (base / "tokenizer_config.json").write_text("{}")
    (base / "model.safetensors").write_bytes(b"fake-base")
    (adapter / "adapter_config.json").write_text("{}")
    (adapter / "adapter_model.safetensors").write_bytes(b"fake-adapter")
    return tmp_path


def test_default_root_is_project_local_not_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for name in (
        "CYBERLLM_MODEL_ROOT", "CYBERLLM_BASE_DIR", "CYBERLLM_ADAPTER_DIR",
    ):
        monkeypatch.delenv(name, raising=False)
    paths = loader.resolve_cyberllm_paths()
    project_root = Path(loader.__file__).resolve().parent.parent.parent
    assert paths.root == project_root / "cyberLLMv1"
    assert paths.base_dir == project_root / "cyberLLMv1" / "base"
    assert paths.adapter_dir in (
        project_root / "cyberLLMv1" / "adapter",
        project_root / "local_models" / "cyberllm" / "v8",
    )
    assert "D:" not in str(paths.root) and "CyberLLM" not in str(paths.root)


def test_custom_root_and_manifest(tmp_path, monkeypatch):
    root = _make_root(tmp_path / "mymodel")
    (root / "manifest.json").write_text(json.dumps({
        "base_model": "Qwen/Qwen3-1.7B",
        "base_revision": "70d244cc86ccca08cf5af4e1e306ecf908b1ad5e",
        "adapter_sha256": hashlib.sha256(b"fake-adapter").hexdigest(),
    }))
    monkeypatch.setenv("CYBERLLM_MODEL_ROOT", str(root))
    for name in ("CYBERLLM_BASE_DIR", "CYBERLLM_ADAPTER_DIR",
                 "CYBERLLM_BASE_MODEL", "CYBERLLM_BASE_REVISION",
                 "CYBERLLM_ADAPTER_SHA256"):
        monkeypatch.delenv(name, raising=False)
    paths = loader.resolve_cyberllm_paths()
    assert paths.root == root
    assert loader.validate_cyberllm_artifacts(paths) == []
    assert loader._adapter_sha_ok(paths) is True


def test_missing_artifacts_reported(tmp_path, monkeypatch):
    monkeypatch.setenv("CYBERLLM_MODEL_ROOT", str(tmp_path / "empty"))
    for name in ("CYBERLLM_BASE_DIR", "CYBERLLM_ADAPTER_DIR"):
        monkeypatch.delenv(name, raising=False)
    paths = loader.resolve_cyberllm_paths()
    missing = loader.validate_cyberllm_artifacts(paths)
    assert any("base model directory missing" in m for m in missing)
    assert any("adapter directory missing" in m for m in missing)


def test_adapter_sha_mismatch_refused(tmp_path, monkeypatch):
    root = _make_root(tmp_path / "bad")
    monkeypatch.setenv("CYBERLLM_MODEL_ROOT", str(root))
    monkeypatch.setenv("CYBERLLM_ADAPTER_SHA256", "0" * 64)
    monkeypatch.delenv("CYBERLLM_BASE_DIR", raising=False)
    monkeypatch.delenv("CYBERLLM_ADAPTER_DIR", raising=False)
    paths = loader.resolve_cyberllm_paths()
    assert loader._adapter_sha_ok(paths) is False


def test_present_but_incomplete_base_fails_clearly(tmp_path, monkeypatch):
    # Audit fix: an existing but empty base dir must not fall through
    # to a cryptic transformers error, and must not trigger a download.
    base = tmp_path / "empty-base"
    base.mkdir()
    adapter = tmp_path / "adapter"
    adapter.mkdir()
    (adapter / "adapter_config.json").write_text("{}")
    (adapter / "adapter_model.safetensors").write_bytes(b"fake-adapter")
    monkeypatch.setenv("CYBERLLM_BASE_DIR", str(base))
    monkeypatch.setenv("CYBERLLM_ADAPTER_DIR", str(adapter))
    monkeypatch.setenv(
        "CYBERLLM_ADAPTER_SHA256",
        hashlib.sha256(b"fake-adapter").hexdigest(),
    )
    monkeypatch.delenv("CYBERLLM_MODEL_ROOT", raising=False)
    status = loader.ensure_loaded()
    assert status.ready is False
    assert "base config.json missing" in (status.reason or "")
    assert "incomplete" in (status.reason or "")
