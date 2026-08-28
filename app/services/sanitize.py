"""Safe rendering of user-generated content.

SECURITY: This module is the ONLY approved way to turn user-authored text into
HTML. Never use Jinja's `| safe` on user content — the whole point of this
module is that it escapes first and then re-introduces a tiny, fixed allowlist
of formatting. There is no code path here that echoes raw user HTML.

Supported (markdown-lite):
    ## / ### headings, paragraphs, hard line breaks, > blockquotes,
    - / * unordered lists, 1. ordered lists, --- horizontal rules,
    **bold**, *italic*, `inline code`, ```fenced code blocks```,
    [label](https://url) links (http/https/mailto only).

Everything else is rendered as literal, escaped text.
"""
from __future__ import annotations

import html
import re
from urllib.parse import urlsplit

from markupsafe import Markup

# URL schemes we are willing to emit in an href / src attribute.
_ALLOWED_SCHEMES = ("http", "https", "mailto")

# Placeholder markers use NUL, which we strip from input first, so user text
# can never forge one.
_CODE_MARK = "\x00C{}\x00"
_INLINE_MARK = "\x00I{}\x00"

_FENCE_RE = re.compile(r"```[ \t]*([A-Za-z0-9_+-]{0,20})[ \t]*\n(.*?)(?:\n)?```", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`([^`\n]+)`")
_BOLD_RE = re.compile(r"\*\*(?=\S)(.+?)(?<=\S)\*\*", re.DOTALL)
_ITALIC_RE = re.compile(r"(?<![\w*])\*(?=\S)([^*\n]+?)(?<=\S)\*(?![\w*])")
_UNDERSCORE_ITALIC_RE = re.compile(r"(?<![\w_])_(?=\S)([^_\n]+?)(?<=\S)_(?![\w_])")
_LINK_RE = re.compile(
    r"\[([^\]\n]{1,200})\]\(((?:[^()\s]|\([^()\s]*\)){1,500})\)"
)
_AUTOLINK_RE = re.compile(r"(?<![\"'>=])\b(https?://[^\s<>\"')]{4,400})")
_HR_RE = re.compile(r"^(?:-{3,}|\*{3,}|_{3,})$")
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
_UL_RE = re.compile(r"^\s*[-*+]\s+(.*)$")
_OL_RE = re.compile(r"^\s*\d{1,3}[.)]\s+(.*)$")
_QUOTE_RE = re.compile(r"^\s*>\s?(.*)$")


def safe_url(raw: str | None, allow_relative: bool = True) -> str:
    """Return `raw` if it is a URL we are willing to link to, else ''.

    Blocks javascript:, data:, vbscript: and any other unexpected scheme, plus
    protocol-relative URLs (//evil.example) and control characters.
    """
    if not raw:
        return ""
    candidate = raw.strip().replace("\x00", "")
    # Strip characters browsers ignore but that can hide a scheme.
    candidate = "".join(ch for ch in candidate if ord(ch) > 0x20 or ch == " ").strip()
    if not candidate:
        return ""
    lowered = candidate.lower()
    if lowered.startswith("//"):
        return ""
    if candidate.startswith("/") and allow_relative:
        # Site-relative path. Reject "/\evil" style tricks.
        return "" if candidate.startswith("/\\") else candidate
    try:
        scheme = (urlsplit(candidate).scheme or "").lower()
    except ValueError:
        return ""
    if scheme in _ALLOWED_SCHEMES:
        return candidate
    if not scheme and allow_relative and not lowered.startswith(("javascript", "data", "vbscript")):
        # Bare "example.com/x" — normalise to https so we never emit a
        # scheme-less href that the browser resolves oddly.
        if re.match(r"^[\w.-]+\.[a-z]{2,}(?:[/?#].*)?$", candidate, re.IGNORECASE):
            return "https://" + candidate
    return ""


def _link_html(label_escaped: str, raw_url: str) -> str:
    url = safe_url(html.unescape(raw_url), allow_relative=False)
    if not url:
        return label_escaped
    return (
        f'<a href="{html.escape(url, quote=True)}" rel="nofollow ugc noopener" '
        f'target="_blank">{label_escaped}</a>'
    )


def _render_inline(text: str, code_slots: list[str]) -> str:
    """Inline formatting on already-HTML-escaped text."""
    # Protect inline code spans before any other inline rule touches them.
    def _stash(match: re.Match) -> str:
        code_slots.append(f"<code>{match.group(1)}</code>")
        return _INLINE_MARK.format(len(code_slots) - 1)

    text = _INLINE_CODE_RE.sub(_stash, text)
    text = _LINK_RE.sub(lambda m: _link_html(m.group(1), m.group(2)), text)
    text = _AUTOLINK_RE.sub(lambda m: _link_html(m.group(1), m.group(1)), text)
    text = _BOLD_RE.sub(r"<strong>\1</strong>", text)
    text = _ITALIC_RE.sub(r"<em>\1</em>", text)
    text = _UNDERSCORE_ITALIC_RE.sub(r"<em>\1</em>", text)
    return text


def _render_block(lines: list[str], code_slots: list[str]) -> str:
    if not lines:
        return ""
    first = lines[0]

    # Whole block is a code placeholder (fenced block extracted earlier).
    if len(lines) == 1 and first.startswith("\x00C") and first.endswith("\x00"):
        return first

    if len(lines) == 1 and _HR_RE.match(first.strip()):
        return "<hr>"

    heading = _HEADING_RE.match(first)
    if heading and len(lines) == 1:
        # Article bodies live under an <h1>; clamp so we never emit h1.
        level = min(max(len(heading.group(1)) + 1, 2), 4)
        return f"<h{level}>{_render_inline(heading.group(2).strip(), code_slots)}</h{level}>"

    if all(_QUOTE_RE.match(ln) for ln in lines):
        inner = "<br>".join(
            _render_inline(_QUOTE_RE.match(ln).group(1).strip(), code_slots) for ln in lines
        )
        return f"<blockquote>{inner}</blockquote>"

    if all(_UL_RE.match(ln) for ln in lines):
        items = "".join(
            f"<li>{_render_inline(_UL_RE.match(ln).group(1).strip(), code_slots)}</li>"
            for ln in lines
        )
        return f"<ul>{items}</ul>"

    if all(_OL_RE.match(ln) for ln in lines):
        items = "".join(
            f"<li>{_render_inline(_OL_RE.match(ln).group(1).strip(), code_slots)}</li>"
            for ln in lines
        )
        return f"<ol>{items}</ol>"

    body = "<br>".join(_render_inline(ln.strip(), code_slots) for ln in lines)
    return f"<p>{body}</p>"


def render_content(raw: str | None) -> Markup:
    """Render user-authored article/comment text to a safe HTML fragment."""
    if not raw:
        return Markup("")

    text = raw.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")

    # 1. Pull fenced code blocks out before escaping so their content is
    #    preserved verbatim (but still escaped) and never parsed as markdown.
    code_blocks: list[str] = []

    def _stash_fence(match: re.Match) -> str:
        lang = match.group(1) or ""
        code = html.escape(match.group(2), quote=True)
        cls = f' class="lang-{html.escape(lang, quote=True)}"' if lang else ""
        code_blocks.append(f"<pre><code{cls}>{code}</code></pre>")
        return "\n\n" + _CODE_MARK.format(len(code_blocks) - 1) + "\n\n"

    text = _FENCE_RE.sub(_stash_fence, text)

    # 2. Escape EVERYTHING. From here on the string contains no user markup.
    text = html.escape(text, quote=True)

    # 3. Group into blocks separated by blank lines.
    inline_code: list[str] = []
    out: list[str] = []
    block: list[str] = []
    for line in text.split("\n"):
        if line.strip():
            block.append(line)
        else:
            out.append(_render_block(block, inline_code))
            block = []
    out.append(_render_block(block, inline_code))

    rendered = "\n".join(part for part in out if part)

    # 4. Restore protected code.
    for idx, snippet in enumerate(inline_code):
        rendered = rendered.replace(_INLINE_MARK.format(idx), snippet)
    for idx, snippet in enumerate(code_blocks):
        rendered = rendered.replace(_CODE_MARK.format(idx), snippet)

    return Markup(rendered)


def strip_formatting(raw: str | None, limit: int = 300) -> str:
    """Plain-text version of user content, for excerpts / meta tags."""
    if not raw:
        return ""
    text = _FENCE_RE.sub(" ", raw.replace("\x00", ""))
    text = _INLINE_CODE_RE.sub(r"\1", text)
    text = _LINK_RE.sub(r"\1", text)
    text = re.sub(r"[*_#>`]+", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "…"


def clean_text(raw: str | None, limit: int | None = None) -> str:
    """Normalise a short single-line user field (display name, tag, title)."""
    if not raw:
        return ""
    text = raw.replace("\x00", "")
    text = re.sub(r"[\r\n\t]+", " ", text)
    text = "".join(ch for ch in text if ord(ch) >= 0x20 or ch == " ")
    text = re.sub(r"\s+", " ", text).strip()
    if limit is not None:
        text = text[:limit]
    return text
