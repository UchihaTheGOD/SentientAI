"""Verification B: file handling, marker, caching."""
from pathlib import Path
from unittest.mock import MagicMock, patch
import time
import pytest
import app.services.prompt_service as pm
from app.services.prompt_service import PROMPT_PATH, get_base_prompt, build_analysis_prompt

def test_4_missing_empty_large(tmp_path, monkeypatch):
    missing = tmp_path / "missing.txt"
    monkeypatch.setattr(pm, "PROMPT_PATH", missing)
    pm._reset_cache()
    with pytest.raises(FileNotFoundError, match="prompt file not found"):
        pm._read_prompt_file()
    with pytest.raises(FileNotFoundError):
        get_base_prompt()
    empty = tmp_path / "empty.txt"
    empty.write_text("", encoding="utf-8")
    monkeypatch.setattr(pm, "PROMPT_PATH", empty)
    pm._reset_cache()
    with pytest.raises(ValueError, match="empty"):
        pm._read_prompt_file()
    ws = tmp_path / "ws.txt"
    ws.write_text("   \n  ", encoding="utf-8")
    monkeypatch.setattr(pm, "PROMPT_PATH", ws)
    pm._reset_cache()
    with pytest.raises(ValueError, match="empty"):
        pm._read_prompt_file()
    big = tmp_path / "big.txt"
    big.write_text("x" * (pm.MAX_PROMPT_BYTES + 1), encoding="utf-8")
    monkeypatch.setattr(pm, "PROMPT_PATH", big)
    pm._reset_cache()
    with pytest.raises(ValueError, match="too large"):
        pm._read_prompt_file()
    pm._reset_cache()

def test_5_marker_to_both_models(tmp_path, monkeypatch):
    MARKER = "PROMPT_PROPAGATION_TEST_7F31"
    base_text = PROMPT_PATH.read_text(encoding="utf-8")
    assert MARKER not in base_text
    tmp_prompt = tmp_path / "prompt.txt"
    tmp_prompt.write_text(base_text + "\n" + MARKER, encoding="utf-8")
    monkeypatch.setattr(pm, "PROMPT_PATH", tmp_prompt)
    import app.api.sentinel as sentinel_api
    monkeypatch.setattr(sentinel_api, "PROMPT_PATH", tmp_prompt)
    pm._reset_cache()
    assert MARKER in pm.get_base_prompt()
    prompt = build_analysis_prompt("TEST LOG 9.9.9.9 probe")
    assert MARKER in prompt and MARKER in prompt.split("<input>")[0]
    import app.services.sentinel_inference as inf
    calls = []
    def fake(m, tok, p, cfg, max_new_tokens=256, timeout_s=12):
        calls.append(p)
        return {"status": "ok", "text": "Summary: t\nIndicators:\n- None\nReasoning: t\nProvisional assessment: likely_benign\nInput status: valid", "tokens": 5, "latency_ms": 1}
    with patch.object(inf, "_generate_for_model", side_effect=fake):
        with patch("app.services.sentinel_loader.get_bundle", return_value={"tokenizer": MagicMock(), "model_a": MagicMock(), "model_b": MagicMock(), "config": {"max_position_embeddings":768}}):
            with patch("app.services.sentinel_loader.get_status", return_value=type("S",(),{"ready":True})()):
                with patch("app.services.sentinel_loader.get_models", return_value={"a": MagicMock(), "b": MagicMock()}):
                    with patch("app.services.sentinel_loader.get_tokenizer", return_value=MagicMock()):
                        inf.run_dual_inference(prompt, max_new_tokens=16, timeout_s=2)
    assert len(calls) == 2 and all(MARKER in c for c in calls) and all("9.9.9.9" in c for c in calls)
    pm._reset_cache()
    assert MARKER not in PROMPT_PATH.read_text(encoding="utf-8")

def test_6_caching_reload(tmp_path, monkeypatch):
    f = tmp_path / "prompt.txt"
    f.write_text("v1 UNTRUSTED provisional", encoding="utf-8")
    monkeypatch.setattr(pm, "PROMPT_PATH", f)
    pm._reset_cache()
    assert "v1" in get_base_prompt()
    time.sleep(0.02)
    f.write_text("v2 UNTRUSTED provisional", encoding="utf-8")
    assert "v2" in get_base_prompt()
    time.sleep(0.02)
    f.write_text("v3 UNTRUSTED provisional", encoding="utf-8")
    info = pm.reload_prompt()
    assert info["reloaded"] is True
    assert "v3" in get_base_prompt()
    pm._reset_cache()

def test_6_mtime_cache():
    pm._reset_cache()
    assert get_base_prompt() == get_base_prompt()
