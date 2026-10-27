"""HTTP client for the existing SentientAI CyberLLM API.

Talks to the real backend only. It never fabricates a verdict: a 503,
429, 422 or 401 is surfaced to the caller as an error carrying the
backend's own reason, so the UI can show it honestly.

Auth uses the website's own forms: GET /login (or /register) to obtain
the signed double-submit CSRF cookie, then POST the form with the
token echoed as a field and as X-CSRF-Token. The session cookie jar
is kept in memory for the process lifetime.
"""

from __future__ import annotations

import re
from typing import Any

import requests

KINDS = ("log", "http_request", "url", "vulnerability")
MAX_LOG_CHARS = 8000


class BackendError(RuntimeError):
    def __init__(self, message: str, status: int | None = None,
                 detail: Any = None):
        super().__init__(message)
        self.status = status
        self.detail = detail


class AuthError(BackendError):
    pass


class ModelUnavailableError(BackendError):
    def __init__(self, reason: str, deterministic_findings: Any = None):
        super().__init__(f"model unavailable: {reason}")
        self.reason = reason
        self.deterministic_findings = deterministic_findings or []


class RateLimitedError(BackendError):
    pass


class ValidationError(BackendError):
    pass


class AdminRequiredError(BackendError):
    pass


def _strip_html(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:300]


class BackendClient:
    def __init__(self, api_base: str):
        self.api_base = api_base.rstrip("/")
        # Direct connection: the backend is local, and proxy env vars
        # have broken localhost requests in the past.
        self.session = requests.Session()
        self.session.trust_env = False
        self.username: str | None = None
        self.password: str | None = None
        self._authed = False

    # -- CSRF -----------------------------------------------------------
    def _csrf_token(self) -> str:
        token = self.session.cookies.get("csrf_token") or ""
        if token:
            return token
        # Fall back to a page's meta tag / hidden input.
        try:
            resp = self.session.get(f"{self.api_base}/login", timeout=10)
            m = re.search(
                r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)',
                resp.text)
            if m:
                return m.group(1)
            m = re.search(
                r'<input[^>]+name=["\']csrf_token["\'][^>]+value=["\']([^"\']+)',
                resp.text)
            if m:
                return m.group(1)
        except requests.RequestException:
            pass
        return ""

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        token = self._csrf_token()
        if token:
            headers["X-CSRF-Token"] = token
        return headers

    # -- auth -----------------------------------------------------------
    def login(self, username: str, password: str) -> tuple[bool, str]:
        try:
            self.session.get(f"{self.api_base}/login", timeout=10)
        except requests.RequestException as exc:
            return False, f"backend not reachable: {exc}"
        token = self._csrf_token()
        try:
            resp = self.session.post(
                f"{self.api_base}/login",
                data={"username": username, "password": password,
                      "next": "", "csrf_token": token},
                headers={"X-CSRF-Token": token} if token else {},
                timeout=15, allow_redirects=False,
            )
        except requests.RequestException as exc:
            return False, f"login request failed: {exc}"
        if resp.status_code == 303:
            self.username, self.password = username, password
            self._authed = True
            return True, "logged in"
        if resp.status_code == 429:
            return False, "login rate-limited by the backend; wait and retry"
        return False, f"login failed (HTTP {resp.status_code}): " + (
            _strip_html(resp.text) or "check the username and password")

    def register(self, username: str, email: str, password: str) -> tuple[bool, str]:
        try:
            self.session.get(f"{self.api_base}/register", timeout=10)
        except requests.RequestException as exc:
            return False, f"backend not reachable: {exc}"
        token = self._csrf_token()
        try:
            resp = self.session.post(
                f"{self.api_base}/register",
                data={"username": username, "email": email,
                      "password": password, "confirm_password": password,
                      "next": "", "csrf_token": token},
                headers={"X-CSRF-Token": token} if token else {},
                timeout=15, allow_redirects=False,
            )
        except requests.RequestException as exc:
            return False, f"register request failed: {exc}"
        if resp.status_code == 303:
            return True, "account created"
        if resp.status_code == 429:
            return False, "registration rate-limited; wait and retry"
        return False, f"registration failed (HTTP {resp.status_code}): " + (
            _strip_html(resp.text) or "see the backend log")

    def ensure_lab_user(self, username: str, password: str,
                        email: str = "seclab@localhost") -> tuple[bool, str]:
        """Log in with the local lab account, creating it on first use."""
        ok, msg = self.login(username, password)
        if ok:
            return True, msg
        ok, msg = self.register(username, email, password)
        if not ok:
            if "already taken" in msg or "already exists" in msg:
                return False, (
                    "a lab account with that username already exists with a "
                    "different password. Change the lab username in Settings, "
                    "or use your own SentientAI login instead."
                )
            return False, f"could not prepare the lab account: {msg}"
        ok, msg = self.login(username, password)
        if ok:
            return True, "lab account created and logged in"
        return False, f"lab account created but login failed: {msg}"

    def ensure_authenticated(self) -> None:
        if self._authed:
            return
        if not self.username or not self.password:
            raise AuthError(
                "not logged in to the backend; enter a SentientAI login "
                "or configure the local lab account in Settings")
        ok, msg = self.login(self.username, self.password)
        if not ok:
            self._authed = False
            raise AuthError(msg)

    # -- API ------------------------------------------------------------
    def readiness(self) -> dict[str, Any]:
        try:
            resp = self.session.get(
                f"{self.api_base}/api/cyberllm/readiness", timeout=10)
        except requests.RequestException as exc:
            raise BackendError(f"backend not reachable: {exc}") from exc
        if resp.status_code != 200:
            raise BackendError(f"readiness returned HTTP {resp.status_code}",
                               status=resp.status_code)
        try:
            data = resp.json()
        except ValueError as exc:
            raise BackendError("readiness returned non-JSON output") from exc
        if not isinstance(data, dict):
            raise BackendError("readiness returned an unexpected payload")
        return data

    def load_model(self) -> dict[str, Any]:
        self.ensure_authenticated()
        try:
            resp = self.session.post(
                f"{self.api_base}/api/cyberllm/readiness/load",
                headers=self._headers(), timeout=180)
        except requests.RequestException as exc:
            raise BackendError(f"load request failed: {exc}") from exc
        if resp.status_code == 403:
            raise AdminRequiredError(
                "explicit model load requires an admin account; the model "
                "still loads automatically on the first analysis")
        if resp.status_code != 200:
            raise BackendError(f"load returned HTTP {resp.status_code}",
                               status=resp.status_code)
        return resp.json()

    def screen(self, text: str) -> dict[str, Any]:
        self.ensure_authenticated()
        return self._post_json("/api/cyberllm/screen", {"text": text})

    def analyze(self, text: str, kind: str = "log",
                max_new_tokens: int | None = None) -> dict[str, Any]:
        if kind not in KINDS:
            raise ValidationError(f"unsupported kind: {kind}")
        if not text or not text.strip():
            raise ValidationError("input text is empty")
        if len(text) > MAX_LOG_CHARS:
            raise ValidationError(
                f"input is {len(text)} chars; the API cap is {MAX_LOG_CHARS}")
        self.ensure_authenticated()
        payload: dict[str, Any] = {"log_text": text, "kind": kind}
        if max_new_tokens is not None:
            payload["max_new_tokens"] = max_new_tokens
        return self._post_json("/api/cyberllm/analyze", payload)

    # -- admin user management (requires an admin session) --------------
    def list_users(self, q: str = "", role: str = "", status: str = "",
                   sort: str = "recent", page: int = 1,
                   per_page: int = 25) -> dict[str, Any]:
        self.ensure_authenticated()
        params = {"q": q, "role": role, "status": status, "sort": sort,
                  "page": page, "per_page": per_page}
        try:
            resp = self.session.get(
                f"{self.api_base}/api/admin/users", params=params, timeout=30)
        except requests.RequestException as exc:
            raise BackendError(f"user list request failed: {exc}") from exc
        return self._handle_admin_response(resp)

    def get_user(self, user_id: int) -> dict[str, Any]:
        self.ensure_authenticated()
        try:
            resp = self.session.get(
                f"{self.api_base}/api/admin/users/{user_id}", timeout=30)
        except requests.RequestException as exc:
            raise BackendError(f"user detail request failed: {exc}") from exc
        return self._handle_admin_response(resp)

    def set_user_role(self, user_id: int, role: str) -> dict[str, Any]:
        return self._admin_patch(f"/api/admin/users/{user_id}/role",
                                 {"role": role})

    def set_user_active(self, user_id: int, is_active: bool) -> dict[str, Any]:
        return self._admin_patch(f"/api/admin/users/{user_id}/active",
                                 {"is_active": is_active})

    def set_user_suspended(self, user_id: int, is_suspended: bool,
                           reason: str | None = None) -> dict[str, Any]:
        return self._admin_patch(f"/api/admin/users/{user_id}/suspend",
                                 {"is_suspended": is_suspended,
                                  "reason": reason})

    def create_user(self, username: str, email: str, password: str,
                    role: str = "user") -> dict[str, Any]:
        self.ensure_authenticated()
        try:
            resp = self.session.post(
                f"{self.api_base}/api/admin/users",
                json={"username": username, "email": email,
                      "password": password, "role": role},
                headers=self._headers(), timeout=30)
        except requests.RequestException as exc:
            raise BackendError(f"create user request failed: {exc}") from exc
        return self._handle_admin_response(resp, created=True)

    def initiate_password_reset(self, user_id: int) -> dict[str, Any]:
        self.ensure_authenticated()
        try:
            resp = self.session.post(
                f"{self.api_base}/api/admin/users/{user_id}/password-reset",
                json={}, headers=self._headers(), timeout=30)
        except requests.RequestException as exc:
            raise BackendError(f"password reset request failed: {exc}") from exc
        return self._handle_admin_response(resp)

    def audit_events(self, limit: int = 50, event_type: str = "",
                     user_id: int | None = None) -> dict[str, Any]:
        self.ensure_authenticated()
        params: dict[str, Any] = {"limit": limit, "event_type": event_type}
        if user_id is not None:
            params["user_id"] = user_id
        try:
            resp = self.session.get(
                f"{self.api_base}/api/admin/audit-events", params=params,
                timeout=30)
        except requests.RequestException as exc:
            raise BackendError(f"audit request failed: {exc}") from exc
        return self._handle_admin_response(resp)

    def _admin_patch(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.ensure_authenticated()
        try:
            resp = self.session.patch(
                f"{self.api_base}{path}", json=payload,
                headers=self._headers(), timeout=30)
        except requests.RequestException as exc:
            raise BackendError(f"admin request failed: {exc}") from exc
        return self._handle_admin_response(resp)

    def _handle_admin_response(self, resp: requests.Response,
                               created: bool = False) -> dict[str, Any]:
        if resp.status_code == 200 or (created and resp.status_code == 201):
            try:
                data = resp.json()
            except ValueError as exc:
                raise BackendError("admin API returned non-JSON output") from exc
            if not isinstance(data, dict):
                raise BackendError("admin API returned an unexpected payload")
            return data
        if resp.status_code == 403:
            raise AdminRequiredError(
                "administrative access denied: sign in as an administrator")
        try:
            detail = resp.json()
        except ValueError:
            detail = {"detail": _strip_html(resp.text)}
        if isinstance(detail, dict):
            detail = detail.get("detail", detail)
        raise BackendError(
            f"admin API returned HTTP {resp.status_code}: {detail}",
            status=resp.status_code, detail=detail)

    def _post_json(self, path: str, payload: dict[str, Any],
                   _retried: bool = False) -> dict[str, Any]:
        try:
            resp = self.session.post(
                f"{self.api_base}{path}", json=payload,
                headers=self._headers(), timeout=600)
        except requests.RequestException as exc:
            raise BackendError(f"request failed: {exc}") from exc
        if resp.status_code == 401 and not _retried and self.username:
            self._authed = False
            self.ensure_authenticated()
            return self._post_json(path, payload, _retried=True)
        if resp.status_code == 200:
            try:
                data = resp.json()
            except ValueError as exc:
                raise BackendError("backend returned non-JSON output") from exc
            if not isinstance(data, dict):
                raise BackendError("backend returned an unexpected payload")
            return data
        try:
            detail = resp.json()
        except ValueError:
            detail = {"detail": _strip_html(resp.text)}
        if resp.status_code == 503:
            reason = ""
            findings = []
            if isinstance(detail, dict):
                inner = detail.get("detail", detail)
                if isinstance(inner, dict):
                    reason = str(inner.get("reason", ""))
                    findings = inner.get("deterministic_findings", [])
            raise ModelUnavailableError(reason or "model not loaded",
                                        findings)
        if resp.status_code == 429:
            raise RateLimitedError(
                "backend rate limit reached; wait before retrying",
                status=429, detail=detail)
        if resp.status_code == 422:
            raise ValidationError(f"input rejected by the backend: {detail}",
                                  status=422, detail=detail)
        if resp.status_code == 401:
            raise AuthError("backend rejected the session; log in again",
                            status=401)
        raise BackendError(
            f"backend returned HTTP {resp.status_code}: {detail}",
            status=resp.status_code, detail=detail)
