"""Path resolution, missing-file, and reload tests for prompt.txt.

Verifies requirements 1-8:
- PROMPT_PATH is BASE_DIR/prompts/prompt.txt derived from __file__
- No hardcoded absolute Windows path
- Normal loading returns file content
- Missing/empty/too-large raises clear error, not silent mock
- Edited file is picked up via mtime and via admin reload (temporary files)
"""
from __future__ import annotations
import time
from pathlib import Path
import pytest
import app.services.prompt_service as prompt_mod
from app.services.prompt_service import BASE_DIR, PROMPT_PATH, MAX_PROMPT_BYTES, get_base_prompt, build_analysis_prompt


@pytest.fixture(autouse=True)
def _reset():
    prompt_mod._reset_cache()
    yield
    prompt_mod._reset_cache()


def test_base_dir_derived_from_file():
    expected = Path(prompt_mod.__file__).resolve().parent.parent.parent
    assert BASE_DIR == expected
    assert PROMPT_PATH == BASE_DIR / "prompts" / "prompt.txt"
    assert PROMPT_PATH.resolve().is_relative_to((BASE_DIR / "prompts").resolve())


def test_no_hardcoded_absolute_path():
    src = Path(prompt_mod.__file__).read_text(encoding="utf-8")
    assert "C:\\Users" not in src
    assert "C:/Users" not in src


def test_normal_loading_matches_file():
    txt = PROMPT_PATH.read_text(encoding="utf-8")
    assert get_base_prompt() == txt


def test_missing_file_raises(tmp_path, monkeypatch):
    missing = tmp_path / "missing_prompt.txt"
    monkeypatch.setattr(prompt_mod, "PROMPT_PATH", missing)
    prompt_mod._reset_cache()
    with pytest.raises(FileNotFoundError, match="prompt file not found"):
        prompt_mod._read_prompt_file()
    with pytest.raises(FileNotFoundError):
        get_base_prompt()
    with pytest.raises(FileNotFoundError):
        prompt_mod.reload_prompt()


def test_too_large_raises(tmp_path, monkeypatch):
    big = tmp_path / "prompt.txt"
    big.write_text("x" * (MAX_PROMPT_BYTES + 1), encoding="utf-8")
    monkeypatch.setattr(prompt_mod, "PROMPT_PATH", big)
    prompt_mod._reset_cache()
    with pytest.raises(ValueError, match="too large"):
        prompt_mod._read_prompt_file()


def test_empty_raises(tmp_path, monkeypatch):
    empty = tmp_path / "prompt.txt"
    empty.write_text("", encoding="utf-8")
    monkeypatch.setattr(prompt_mod, "PROMPT_PATH", empty)
    prompt_mod._reset_cache()
    with pytest.raises(ValueError, match="empty"):
        prompt_mod._read_prompt_file()
    ws = tmp_path / "ws.txt"
    ws.write_text("   \n  ", encoding="utf-8")
    monkeypatch.setattr(prompt_mod, "PROMPT_PATH", ws)
    prompt_mod._reset_cache()
    with pytest.raises(ValueError, match="empty"):
        prompt_mod._read_prompt_file()


def test_reload_picks_up_edit(tmp_path, monkeypatch):
    f = tmp_path / "prompt.txt"
    f.write_text("v1 UNTRUSTED provisional", encoding="utf-8")
    monkeypatch.setattr(prompt_mod, "PROMPT_PATH", f)
    prompt_mod._reset_cache()
    assert "v1" in get_base_prompt()
    time.sleep(0.02)
    f.write_text("v2 UNTRUSTED provisional", encoding="utf-8")
    assert "v2" in get_base_prompt()
    time.sleep(0.02)
    f.write_text("v3 UNTRUSTED provisional", encoding="utf-8")
    info = prompt_mod.reload_prompt()
    assert info["reloaded"] is True
    assert "v3" in get_base_prompt()
    assert info["chars"] == len(get_base_prompt())


def test_api_reload_reflects_edit(tmp_path, monkeypatch, admin, admin_client):
    f = tmp_path / "prompt.txt"
    f.write_text("API v1 UNTRUSTED provisional", encoding="utf-8")
    monkeypatch.setattr(prompt_mod, "PROMPT_PATH", f)
    import app.api.sentinel as sentinel_api
    monkeypatch.setattr(sentinel_api, "PROMPT_PATH", f)
    prompt_mod._reset_cache()
    r = admin_client._client.post("/api/sentinel/prompt/reload", headers={"X-CSRF-Token": admin_client._csrf()})
    assert r.status_code == 200
    v1chars = r.json()["chars"]
    time.sleep(0.02)
    f.write_text("API v2 UNTRUSTED provisional longer", encoding="utf-8")
    r2 = admin_client._client.post("/api/sentinel/prompt/reload", headers={"X-CSRF-Token": admin_client._csrf()})
    assert r2.status_code == 200
    assert r2.json()["chars"] != v1chars
    r3 = admin_client._client.get("/api/sentinel/prompt/status")
    assert r3.status_code == 200
    assert "v2" in r3.json()["preview"]


def test_api_missing_returns_500(tmp_path, monkeypatch, admin, admin_client):
    missing = tmp_path / "missing.txt"
    monkeypatch.setattr(prompt_mod, "PROMPT_PATH", missing)
    import app.api.sentinel as sentinel_api
    monkeypatch.setattr(sentinel_api, "PROMPT_PATH", missing)
    prompt_mod._reset_cache()
    r = admin_client._client.get("/api/sentinel/prompt/status")
    assert r.status_code == 500
    assert "prompt file not found" in r.text.lower()
    r2 = admin_client._client.post("/api/sentinel/prompt/reload", headers={"X-CSRF-Token": admin_client._csrf()})
    assert r2.status_code == 500
    r3 = admin_client._client.get("/api/sentinel/readiness")
    assert r3.status_code == 200
    data = r3.json()
    assert data["prompt_chars"] is None
    assert "prompt_error" in data
    payload = {"log_text": "2024-01-01 INFO 1.2.3.4 login", "max_new_tokens": 16}
    r4 = admin_client._client.post("/api/sentinel/analyze", json=payload, headers={"X-CSRF-Token": admin_client._csrf()})
    assert r4.status_code == 500
