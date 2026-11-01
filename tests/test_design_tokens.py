"""Stage 2 design-token tests: WCAG contrast for every text/background
pair the Technical Editorial system actually renders, in both themes.

Parses app/static/css/nx-tokens.css directly, so a token change that
breaks contrast fails here instead of shipping silently. AA requires
4.5:1 for normal text; body text additionally aims for 7:1 (AAA).
"""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TOKENS = REPO / "app" / "static" / "css" / "nx-tokens.css"
BASE = REPO / "app" / "templates" / "base_public.html"

VAR_RE = re.compile(r"--(nx-[a-z0-9-]+):\s*(#[0-9a-fA-F]{6})")


def _block(text, start_marker, end_marker):
    start = text.index(start_marker)
    end = text.index(end_marker, start) if end_marker else len(text)
    return text[start:end]


def _tokens(block):
    return {name: value.lower() for name, value in VAR_RE.findall(block)}


def _luminance(hex_color):
    rgb = [int(hex_color[i:i + 2], 16) / 255.0 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def _ratio(fg, bg):
    lf, lb = _luminance(fg), _luminance(bg)
    hi, lo = max(lf, lb), min(lf, lb)
    return (hi + 0.05) / (lo + 0.05)


def _load():
    text = TOKENS.read_text()
    light = _tokens(_block(text, ":root,", ':root[data-theme="dark"]'))
    dark = _tokens(_block(text, ':root[data-theme="dark"]',
                          "@media (prefers-color-scheme: dark)"))
    return light, dark


# (foreground token, background token, minimum ratio)
PAIRS = [
    ("nx-text", "nx-canvas", 7.0),            # body text aims for AAA
    ("nx-text-secondary", "nx-canvas", 4.5),
    ("nx-text-muted", "nx-canvas", 4.5),
    ("nx-accent", "nx-canvas", 4.5),          # link text
    ("nx-accent-hover", "nx-accent-soft", 4.5),  # badge / active chip text
    ("nx-success", "nx-success-soft", 4.5),
    ("nx-warning", "nx-warning-soft", 4.5),
    ("nx-danger", "nx-danger-soft", 4.5),
    ("nx-info", "nx-info-soft", 4.5),
    ("nx-on-accent", "nx-accent", 4.5),       # primary button text
    ("nx-text", "nx-surface", 4.5),           # text on cards
    ("nx-text-muted", "nx-surface", 4.5),
]


def test_token_files_exist_and_are_linked():
    for name in ("nx-tokens.css", "nx-components.css", "nx-layout.css"):
        assert (REPO / "app" / "static" / "css" / name).is_file(), name
    html = BASE.read_text()
    for name in ("nx-tokens.css", "nx-components.css", "nx-layout.css"):
        assert f"/static/css/{name}" in html, name


def test_light_theme_contrast():
    light, _ = _load()
    for fg, bg, minimum in PAIRS:
        ratio = _ratio(light[fg], light[bg])
        assert ratio >= minimum, f"light {fg} on {bg}: {ratio:.2f} < {minimum}"


def test_dark_theme_contrast():
    _, dark = _load()
    for fg, bg, minimum in PAIRS:
        ratio = _ratio(dark[fg], dark[bg])
        assert ratio >= minimum, f"dark {fg} on {bg}: {ratio:.2f} < {minimum}"


def test_on_accent_token_defined_in_both_themes():
    light, dark = _load()
    assert light["nx-on-accent"] == "#ffffff"
    assert dark["nx-on-accent"] == "#17171c"
