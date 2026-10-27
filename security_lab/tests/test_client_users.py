"""Admin client error mapping (no live backend needed)."""

import json

import pytest
import requests

from ..client import AdminRequiredError, AuthError, BackendClient, BackendError


def _response(status, payload=None, raw=None):
    resp = requests.Response()
    resp.status_code = status
    if payload is not None:
        resp._content = json.dumps(payload).encode()
        resp.headers["Content-Type"] = "application/json"
    else:
        resp._content = (raw or "").encode()
    return resp


def _client():
    return BackendClient("http://127.0.0.1:1")


def test_admin_response_success():
    client = _client()
    assert client._handle_admin_response(
        _response(200, {"users": []})) == {"users": []}
    assert client._handle_admin_response(
        _response(201, {"id": 1}), created=True) == {"id": 1}


def test_admin_response_403_maps_to_admin_required():
    with pytest.raises(AdminRequiredError):
        _client()._handle_admin_response(_response(403, {"detail": "no"}))


def test_admin_response_error_carries_backend_detail():
    with pytest.raises(BackendError, match="already taken"):
        _client()._handle_admin_response(
            _response(409, {"detail": "Username already taken."}))


def test_admin_response_non_json_is_still_an_error():
    with pytest.raises(BackendError):
        _client()._handle_admin_response(_response(500, raw="oops"))


def test_admin_calls_require_authentication():
    client = _client()
    with pytest.raises(AuthError, match="not logged in"):
        client.list_users()
    with pytest.raises(AuthError, match="not logged in"):
        client.set_user_role(1, "admin")
    with pytest.raises(AuthError, match="not logged in"):
        client.create_user("a", "a@example.test", "StrongPass1")
