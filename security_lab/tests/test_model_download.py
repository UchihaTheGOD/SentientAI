"""Tests for security_lab/model_download.py (no network, no GUI).

Covers the fail-closed SHA verification, the model-state ladder, and the
disk-space check. Download paths that need the network (HF snapshot,
Kaggle CLI, HTTPS) are NOT exercised here; they are manual/Windows checks.
"""

import hashlib
from pathlib import Path

import pytest

from security_lab import model_download as md

V8_SHA = "d624ed793a45a64cb541577441c87c7d2feb83c37a84da057d1c15e58e45a5b1"


def _make_adapter(adapter_dir: Path, payload: bytes = b"fake-adapter") -> str:
    adapter_dir.mkdir(parents=True, exist_ok=True)
    (adapter_dir / "adapter_model.safetensors").write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def test_state_missing_on_empty_dirs(tmp_path):
    assert md.model_state(tmp_path / "base", tmp_path / "adapter", V8_SHA) == (
        md.STATE_MISSING)


def test_verify_fails_closed_on_empty_sha(tmp_path):
    adapter = tmp_path / "adapter"
    _make_adapter(adapter)
    ok, _, _ = md.verify_adapter(adapter, "")
    assert ok is False


def test_verify_fails_closed_on_missing_file(tmp_path):
    ok, _, _ = md.verify_adapter(tmp_path / "adapter", V8_SHA)
    assert ok is False


def test_verify_passes_on_matching_sha(tmp_path):
    adapter = tmp_path / "adapter"
    real = _make_adapter(adapter)
    ok, actual, _ = md.verify_adapter(adapter, real)
    assert ok is True
    assert actual == real


def test_verify_fails_on_mismatch(tmp_path):
    adapter = tmp_path / "adapter"
    _make_adapter(adapter)
    ok, _, message = md.verify_adapter(adapter, "0" * 64)
    assert ok is False
    assert "mismatch" in message.lower()


def test_state_verified_when_base_and_adapter_present(tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    (base / "config.json").write_text("{}")
    (base / "model-00001-of-00002.safetensors").write_bytes(b"fake-base")
    adapter = tmp_path / "adapter"
    real = _make_adapter(adapter)
    assert md.model_state(base, adapter, real) == md.STATE_VERIFIED


def test_state_corrupted_when_sha_mismatches(tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    (base / "config.json").write_text("{}")
    (base / "model-00001-of-00002.safetensors").write_bytes(b"fake-base")
    adapter = tmp_path / "adapter"
    _make_adapter(adapter)
    assert md.model_state(base, adapter, "0" * 64) == md.STATE_CORRUPTED


def test_state_incomplete_when_only_adapter_present(tmp_path):
    adapter = tmp_path / "adapter"
    _make_adapter(adapter)
    assert md.model_state(tmp_path / "base", adapter, V8_SHA) == (
        md.STATE_INCOMPLETE)


def test_disk_space_check_reports_free_bytes(tmp_path):
    ok, free = md.check_disk_space(tmp_path, 0)
    assert ok is True
    assert free > 0


def test_disk_space_check_fails_when_huge(tmp_path):
    # Request far more than any disk has; must fail, not crash.
    ok, _ = md.check_disk_space(tmp_path, 10 ** 18)
    assert ok is False


def test_sha256_file_matches_hashlib(tmp_path):
    target = tmp_path / "x.bin"
    target.write_bytes(b"abc123")
    assert md.sha256_file(target) == hashlib.sha256(b"abc123").hexdigest()
