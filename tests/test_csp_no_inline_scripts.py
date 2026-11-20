"""CSP regression: no inline scripts or event handlers in templates.

After the script-src 'self' fix, any inline <script> or onclick= in a
template would be blocked by the browser (not just by a test), so this
scan fails the build rather than silently shipping dead UI code.
"""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "app" / "templates"
STATIC_JS = ROOT / "app" / "static" / "js"


def test_no_inline_script_or_onclick_in_templates():
    offenders = []
    for path in sorted(TEMPLATES.rglob("*.html")):
        text = path.read_text(encoding="utf-8")
        if re.search(r"<script(?!\s+src=)[^>]*>", text):
            offenders.append(str(path))
        if "onclick=" in text:
            offenders.append(str(path) + " (onclick)")
    assert offenders == [], offenders


def test_every_template_script_src_file_exists():
    missing = []
    for path in sorted(TEMPLATES.rglob("*.html")):
        for src in re.findall(r'<script\s+src="(/static/js/[^"]+)"', path.read_text(encoding="utf-8")):
            name = pathlib.Path(src).name
            if not (STATIC_JS / name).exists():
                missing.append(f"{path}: {src}")
    assert missing == [], missing


def test_csp_header_has_no_script_unsafe_inline(client):
    headers = client.get("/").headers
    csp = headers["Content-Security-Policy"]
    script_src = [p for p in csp.split("; ") if p.startswith("script-src")]
    assert script_src and "unsafe-inline" not in script_src[0]
