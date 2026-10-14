"""ATTACT scope enforcement tests."""
from __future__ import annotations
import pytest
from ATTACT.scope import TargetConfig, validate_target, validate_url, ScopeError

def test_loopback_allowed():
    cfg=TargetConfig(target_url="http://127.0.0.1:8000", confirm_authorized=True)
    assert validate_target(cfg)

def test_localhost_allowed():
    assert validate_url("http://localhost:8000", set())

def test_non_loopback_blocked_without_allowlist():
    with pytest.raises(ScopeError, match="not loopback"):
        validate_url("http://93.184.216.34/", set())

def test_allowlisted_host_allowed():
    # even a public IP is allowed when explicitly allowlisted
    assert validate_url("http://93.184.216.34/", {"93.184.216.34"})

def test_confirm_required():
    cfg=TargetConfig(target_url="http://127.0.0.1:8000", confirm_authorized=False)
    with pytest.raises(ScopeError, match="confirm"):
        validate_target(cfg)

def test_target_required():
    with pytest.raises(ScopeError, match="No --target"):
        validate_target(TargetConfig(target_url="", confirm_authorized=True))

def test_non_http_rejected():
    with pytest.raises(ScopeError, match="Only http"):
        validate_url("ftp://127.0.0.1/", set())

def test_embedded_creds_rejected():
    with pytest.raises(ScopeError, match="credentials"):
        validate_url("http://user:pass@127.0.0.1/", set())

def test_redirect_revalidation_blocks_external():
    from ATTACT.scope import validate_redirect_url
    with pytest.raises(ScopeError, match="Redirect blocked|not loopback"):
        validate_redirect_url("http://93.184.216.34/evil", set())
