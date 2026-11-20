"""Theme (dark/light/system) — API + header + CSS smoke tests.

Covers Phase G requirements without browser JS execution:
- explicit Light/Dark overrides
- System mode resolves per media query (server returns system, client JS resolves)
- persistence (server for auth, localStorage contract via JS presence)
- selector on public + admin, readable dark overrides, no regressions.
"""
import pathlib
import re

BASE = pathlib.Path(__file__).resolve().parent.parent / "app" / "templates" / "base_public.html"
THEME_JS = pathlib.Path(__file__).resolve().parent.parent / "app" / "static" / "js" / "theme.js"
THEME_CSS = pathlib.Path(__file__).resolve().parent.parent / "app" / "static" / "css" / "theme.css"
THEME_JS_TEXT = THEME_JS.read_text(encoding="utf-8") if THEME_JS.exists() else ""
THEME_CSS_TEXT = THEME_CSS.read_text(encoding="utf-8") if THEME_CSS.exists() else ""


def test_theme_selector_in_base():
    t = BASE.read_text(encoding="utf-8")
    assert "theme_selector" in t, "base_public missing theme_selector include"
    assert "theme.js" in t, "theme.js not included"
    assert "theme.css" in t
    # The no-flash script is now an external file (CSP script-src 'self'
    # only, no unsafe-inline) — it must still be referenced from base.
    assert "theme_bootstrap.js" in t


def test_inline_no_flash_script_sets_data_theme():
    # Behaviour preserved, location changed for CSP: the script lives in
    # app/static/js/theme_bootstrap.js and must be referenced from <head>
    # before the first stylesheet to avoid FOUC.
    bootstrap = pathlib.Path(__file__).resolve().parent.parent / "app" / "static" / "js" / "theme_bootstrap.js"
    assert bootstrap.exists()
    js = bootstrap.read_text(encoding="utf-8")
    assert "sentient_theme" in js
    assert "prefers-color-scheme" in js
    assert "data-theme" in js
    t = BASE.read_text(encoding="utf-8")
    assert "theme_bootstrap.js" in t
    assert t.index("theme_bootstrap.js") < t.index("theme.css")


def test_theme_js_implements_three_modes():
    assert THEME_JS.exists()
    assert "system" in THEME_JS_TEXT and "light" in THEME_JS_TEXT and "dark" in THEME_JS_TEXT
    assert "localStorage" in THEME_JS_TEXT
    assert "prefers-color-scheme" in THEME_JS_TEXT
    assert "matchMedia" in THEME_JS_TEXT
    assert "/api/user/theme" in THEME_JS_TEXT


def test_theme_css_has_light_and_dark_palettes():
    assert THEME_CSS.exists()
    assert "--bg" in THEME_CSS_TEXT
    assert '[data-theme="dark"]' in THEME_CSS_TEXT or "data-theme=\"dark\"" in THEME_CSS_TEXT
    assert "prefers-color-scheme: dark" in THEME_CSS_TEXT
    assert "color-scheme" in THEME_CSS_TEXT


def test_theme_js_persistence_contract():
    assert "setStored" in THEME_JS_TEXT or "localStorage.setItem" in THEME_JS_TEXT
    assert "getStored" in THEME_JS_TEXT or "localStorage.getItem" in THEME_JS_TEXT


def test_selector_accessibility_markers():
    part = pathlib.Path(__file__).resolve().parent.parent / "app" / "templates" / "partials" / "theme_selector.html"
    assert part.exists()
    t = part.read_text(encoding="utf-8")
    assert "aria-pressed" in t
    assert "aria-label" in t
    assert t.count("data-theme-value") >= 3


def test_csp_script_src_has_no_unsafe_inline():
    # Theme script is external now, so script-src must not allow inline
    # scripts; style-src still needs 'unsafe-inline' for style attributes.
    main = (pathlib.Path(__file__).resolve().parent.parent / "app" / "main.py").read_text(encoding="utf-8")
    script_src = [line for line in main.splitlines() if "script-src" in line]
    assert script_src and "unsafe-inline" not in script_src[0]
    style_src = [line for line in main.splitlines() if "style-src" in line]
    assert style_src and "unsafe-inline" in style_src[0]


def _get_theme_helpers():
    from app.api.theme import VALID_THEMES
    return VALID_THEMES


def test_theme_api_validation(client):
    # anonymous cannot POST theme (auth required) but GET resolve works
    r = client.get("/api/user/theme-resolve")
    assert r.status_code == 200
    assert r.json()["theme"] in ("system", "light", "dark")


def test_authenticated_theme_persist_roundtrip(admin_client):
    # set via API, read back
    for choice in ("light", "dark", "system"):
        r = admin_client.post("/api/user/theme", json={"theme": choice})
        assert r.status_code == 200, r.text[:500]
        assert r.json()["theme"] == choice
        r2 = admin_client.get("/api/user/theme")
        assert r2.status_code == 200
        assert r2.json()["theme"] == choice
    # invalid
    r = admin_client.post("/api/user/theme", json={"theme": "banana"})
    assert r.status_code in (400, 422)


def test_anonymous_theme_change_allowed_via_localstorage_contract():
    # anonymous uses localStorage; server resolve returns system unauthenticated
    from tests.conftest import Client
    from app.main import create_app
    app = create_app()
    anon = Client(app)
    r = anon._client.get("/api/user/theme-resolve")
    assert r.status_code == 200
    assert r.json()["authenticated"] is False


def test_admin_pages_contain_selector(admin_client):
    for path in ("/admin", "/admin/security"):
        r = admin_client.get(path)
        assert r.status_code == 200
        assert "theme-selector" in r.text or "data-theme-selector" in r.text, f"selector missing on {path}"


def test_public_pages_contain_selector(client):
    for path in ("/", "/explore", "/blog", "/community"):
        r = client.get(path)
        assert r.status_code == 200, path
        assert "data-theme-selector" in r.text, f"selector missing on {path}"
