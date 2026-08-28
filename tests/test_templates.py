"""Every template must compile, and every link in the chrome must resolve.

Jinja errors in a template only surface when a route renders it, so a typo in a
page nobody visited during a test run ships silently. This module walks
`app/templates` and compiles each file, and separately checks that the paths the
shared navigation links to are actually routed — the failure mode that left
`/activity` in the header dropdown with no route behind it.
"""
from __future__ import annotations

import pathlib
import re

import pytest
from jinja2 import TemplateSyntaxError

from app.template_env import templates

TEMPLATE_ROOT = pathlib.Path("app/templates")

TEMPLATE_PATHS = sorted(
    p.relative_to(TEMPLATE_ROOT).as_posix()
    for p in TEMPLATE_ROOT.rglob("*.html")
)


def test_there_are_templates_to_check():
    # A guard on the guard: if the glob ever finds nothing, the parametrised
    # test below would pass by vacuum.
    assert len(TEMPLATE_PATHS) > 20


@pytest.mark.parametrize("name", TEMPLATE_PATHS)
def test_the_template_compiles(name):
    try:
        templates.env.get_template(name)
    except TemplateSyntaxError as exc:  # pragma: no cover - only on a real break
        pytest.fail(f"{name}:{exc.lineno}: {exc.message}")


# ---------------------------------------------------------------------------
# The chrome does not link into nothing
# ---------------------------------------------------------------------------

_HREF_RE = re.compile(r'href="(/[^"{#?]*)"')

# Paths that are deliberately not FastAPI routes.
_NOT_ROUTES = {"/static"}


def _routed_paths(app) -> set[str]:
    return {getattr(r, "path", "") for r in app.routes}


@pytest.mark.parametrize("name", ["base_public.html", "partials/nav.html"])
def test_navigation_links_point_at_real_routes(app, name):
    path = TEMPLATE_ROOT / name
    if not path.exists():
        pytest.skip(f"{name} is not part of this layout")

    source = path.read_text(encoding="utf-8")
    routed = _routed_paths(app)
    missing = sorted(
        href for href in set(_HREF_RE.findall(source))
        if href not in routed
        and not any(href.startswith(prefix) for prefix in _NOT_ROUTES)
    )
    assert not missing, f"{name} links to unrouted paths: {missing}"
