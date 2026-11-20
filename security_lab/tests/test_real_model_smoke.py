"""Real-model smoke test: skipped unless explicitly enabled.

Run with CYBERLLM_REAL_MODEL=1 and a backend whose model is ready.
Skips (never fakes) when the model is unavailable, so the suite stays
green on machines without the 1.7B weights.
"""

import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("CYBERLLM_REAL_MODEL") != "1",
    reason="real-model smoke test requires CYBERLLM_REAL_MODEL=1")


def test_real_model_analyze():
    from ..client import BackendClient
    from ..config import load_settings, user_data_dir

    client = BackendClient(load_settings(user_data_dir()).api_base)
    data = client.readiness()
    if not data.get("ready"):
        pytest.skip(f"model not ready: {data.get('state')} "
                    f"{data.get('reason')}")
    out = client.analyze(
        "Oct 24 10:12:03 workstation sudo: alice : TTY=pts/0 ; "
        "PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update",
        "log")
    assert out.get("classification") in ("likely_benign", "needs_review",
                                         "likely_threat")
    assert out.get("parse_ok") is True
