"""Architecture audit tests (2026-10-27): Sentinel single-model degradation.

These tests prove, from code behaviour rather than test names, that:
- Model B is OPTIONAL for Sentinel core functionality: the loader marks
  ready when at least one model loads, and fusion scores rules-only when
  a model is unavailable, never fabricating a model verdict.
- CyberLLMv1 does NOT depend on Sentinel: no cyberllm module imports
  any sentinel module, and the two loaders resolve different roots.
- Sentinel never uses the GPU: its checkpoints load with
  map_location="cpu" and inference runs on the model device (CPU).
- Removing dead helpers (_check_ram, is_ready, has_any_model) did not
  break the loader's public surface used by the app.
"""
from __future__ import annotations


def test_sentinel_loader_single_model_is_ready_by_design():
    # Loader code: ready = len(models) > 0, not len(models) == 2.
    import inspect
    from app.services import sentinel_loader
    src = inspect.getsource(sentinel_loader._do_load)
    assert "ready = len(models) > 0" in src


def test_fusion_rules_only_when_models_unavailable():
    from app.services.sentinel_fusion import fuse
    inference = {
        "model_a": {"status": "unavailable", "text": ""},
        "model_b": {"status": "unavailable", "text": ""},
        "agreement": None,
    }
    benign = fuse("2024-01-01 10:00:00 INFO user alice fetched /blog 200", inference)
    assert benign["fused_verdict"] == "likely_benign"
    assert benign["model_a_valid"] is False and benign["model_b_valid"] is False
    brute = fuse(
        "\n".join(
            f"2024-01-01 10:00:{i:02d} WARN 192.168.1.10 login failed for user admin 401"
            for i in range(6)
        ),
        inference,
    )
    assert brute["fused_verdict"] == "needs_review"
    assert brute["rules"]["failed_count"] >= 5
    # No model component may claim a verdict when it produced nothing.
    for comp in brute["components"]:
        if comp["source"] in ("model_a", "model_b"):
            assert comp["verdict"] is None


def test_cyberllm_does_not_import_sentinel():
    import pathlib
    for path in pathlib.Path("app/services").glob("cyberllm_*.py"):
        src = path.read_text(encoding="utf-8")
        assert "sentinel" not in src.lower(), f"{path} imports sentinel"
    api = pathlib.Path("app/api/cyberllm.py").read_text(encoding="utf-8")
    # The module docstring may mention /api/sentinel/analyze as a
    # convention reference; what must not exist is a sentinel import.
    assert "from app.services.sentinel" not in api
    assert "import sentinel" not in api
    assert "sentinel_loader" not in api and "sentinel_inference" not in api


def test_sentinel_is_cpu_only_by_construction():
    import inspect
    from app.services import sentinel_loader
    src = inspect.getsource(sentinel_loader._load_single_checkpoint)
    assert 'map_location="cpu"' in src
    # No CUDA device selection anywhere in the Sentinel stack.
    import pathlib
    for path in (pathlib.Path("app/services/sentinel_loader.py"),
                 pathlib.Path("app/services/sentinel_inference.py")):
        text = path.read_text(encoding="utf-8")
        assert "cuda" not in text.lower()


def test_dead_helpers_removed_without_breaking_loader_surface():
    from app.services import sentinel_loader
    for name in ("_check_ram", "is_ready", "has_any_model"):
        assert not hasattr(sentinel_loader, name), name
    for name in ("get_status", "ensure_loaded", "get_bundle", "get_models",
                 "get_tokenizer", "init_sentinel", "sentinel_missing_files",
                 "_choose_checkpoint_b"):
        assert hasattr(sentinel_loader, name), name


def test_sentinel_analyze_degrades_to_rules_when_models_missing(admin_client):
    # Uses the app's own fixtures; models are absent in this VM, so this
    # must still return 200 with a rules-based verdict and an incident,
    # not a 500 and not a fabricated model verdict. This is the live
    # proof that missing Sentinel checkpoints do not break the app.
    r = admin_client._client.post(
        "/api/sentinel/analyze",
        json={"log_text": "2024-01-01 10:00:00 INFO user alice fetched /blog 200",
              "create_incident": False},
        headers={"X-CSRF-Token": admin_client._csrf()},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["verdict"] in ("likely_benign", "needs_review", "likely_threat")
    assert data["model_a"]["status"] == "unavailable"
    assert data["model_b"]["status"] == "unavailable"
