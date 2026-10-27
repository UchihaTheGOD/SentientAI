"""Settings round-trip and model-identity pinning."""

from ..config import (EXPECTED_ADAPTER_SHA256, EXPECTED_BASE_REVISION,
                      Settings, load_settings, save_settings)


def test_settings_round_trip(tmp_path):
    s = Settings(api_port=8123, api_base="http://127.0.0.1:8123",
                 allowlist=["example.com", "127.0.0.1"],
                 lab_username="tester", device="cpu")
    save_settings(s, tmp_path)
    loaded = load_settings(tmp_path)
    assert loaded.api_port == 8123
    assert loaded.api_base == "http://127.0.0.1:8123"
    assert loaded.allowlist == ["example.com", "127.0.0.1"]
    assert loaded.lab_username == "tester"
    assert loaded.device == "cpu"
    # Settings are small JSON (paths + the expected adapter SHA), never
    # model weights: the file must stay tiny and binary-free.
    blob = (tmp_path / "settings.json").read_bytes()
    assert len(blob) < 10_000
    assert b"adapter_sha256" in blob  # the expected hash, not weights


def test_pinned_model_identity():
    s = Settings()
    assert s.base_revision == EXPECTED_BASE_REVISION
    assert s.adapter_sha256 == EXPECTED_ADAPTER_SHA256
    assert s.adapter_sha256 == (
        "d624ed793a45a64cb541577441c87c7d2feb83c37a84da057d1c15e58e45a5b1")


def test_defaults_are_safe():
    s = Settings()
    assert s.rate_limit_seconds > 0
    assert s.max_requests_per_scan > 0
    assert s.max_workers >= 1
    assert s.local_lab_enabled is False
    assert s.allowlist == []
