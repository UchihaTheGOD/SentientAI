"""Output safety for user-generated content.

The unit tests cover `app/services/sanitize.py` directly; the integration tests
push the same payloads through the real post and comment forms and assert that
what comes back out of the rendered page is inert. Stored XSS is the one the
brief calls out specifically, so a post body and a comment body are both
round-tripped through the database.
"""
from __future__ import annotations

import re

import pytest

from app.models.blog_post import POST_PUBLISHED, BlogPost
from app.services.sanitize import clean_text, render_content, safe_url, strip_formatting

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<iframe src=javascript:alert(1)></iframe>",
    "<body onload=alert(1)>",
    "<a href=\"javascript:alert(1)\">click</a>",
    "<div style=\"background:url(javascript:alert(1))\">x</div>",
    "\"><script>alert(1)</script>",
    "<img src=\"x\" onerror=\"alert(String.fromCharCode(88,83,83))\">",
    "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></object>",
    "<style>body{background:url('javascript:alert(1)')}</style>",
    "<math><mtext><script>alert(1)</script></mtext></math>",
]


# Every tag the sanitizer is allowed to emit. Anything else in its output is a
# bug, and anything user-authored that reaches the page must arrive as escaped
# text rather than as one of these.
ALLOWED_TAGS = {
    "p", "br", "strong", "em", "code", "pre", "ul", "ol", "li",
    "blockquote", "h2", "h3", "h4", "hr", "a",
}

_TAG_RE = re.compile(r"<(/?)([A-Za-z][A-Za-z0-9]*)((?:[^>\"']|\"[^\"]*\"|'[^']*')*)>")


def _tags(rendered: str) -> list[tuple[str, str]]:
    """(tag name, attribute string) for every tag in a rendered fragment."""
    return [(name.lower(), attrs) for _, name, attrs in _TAG_RE.findall(rendered)]


# ---------------------------------------------------------------------------
# The sanitizer itself
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", XSS_PAYLOADS)
def test_no_payload_survives_as_markup(payload):
    rendered = str(render_content(payload))

    # Nothing outside the allowlist is emitted, no event handler attribute
    # survives, and no dangerous scheme appears inside an attribute. Checking
    # the parsed tags rather than raw substrings matters: the escaped text
    # legitimately contains the characters "onerror=", and that is inert.
    for name, attrs in _tags(rendered):
        assert name in ALLOWED_TAGS, f"{payload!r} produced <{name}>"
        assert not re.search(r"\bon[a-z]+\s*=", attrs, re.IGNORECASE), attrs
        assert "javascript:" not in attrs.lower()
        assert "data:" not in attrs.lower()

    # And the payload's own markup is present only as escaped text.
    assert payload not in rendered
    assert "&lt;" in rendered


def test_allowed_markdown_still_renders():
    rendered = str(render_content(
        "## Heading\n\n**bold** and *italic* and `code`\n\n- one\n- two\n\n> quoted"
    ))
    assert "<h3>Heading</h3>" in rendered
    assert "<strong>bold</strong>" in rendered
    assert "<em>italic</em>" in rendered
    assert "<code>code</code>" in rendered
    assert "<ul><li>one</li><li>two</li></ul>" in rendered
    assert "<blockquote>quoted</blockquote>" in rendered


def test_fenced_code_is_escaped_not_executed():
    rendered = str(render_content("```\n<script>alert(1)</script>\n```"))
    assert "<pre><code>" in rendered
    assert "&lt;script&gt;" in rendered
    assert "<script>" not in rendered


def test_markdown_link_only_accepts_safe_schemes():
    assert 'href="https://example.com"' in str(render_content("[ok](https://example.com)"))
    dangerous = str(render_content("[bad](javascript:alert(1))"))
    assert "javascript:" not in dangerous.lower()
    assert "href" not in dangerous


@pytest.mark.parametrize("raw", [
    "javascript:alert(1)",
    "JaVaScRiPt:alert(1)",
    "java\tscript:alert(1)",
    "data:text/html;base64,PHNjcmlwdD4=",
    "vbscript:msgbox(1)",
    "//evil.example/phish",
    "/\\evil.example",
])
def test_safe_url_rejects_dangerous_values(raw):
    assert safe_url(raw) == ""


@pytest.mark.parametrize("raw", [
    "https://example.com/page",
    "http://example.com",
    "mailto:someone@example.com",
    "/local/path",
])
def test_safe_url_allows_ordinary_values(raw):
    assert safe_url(raw) == raw


def test_clean_text_flattens_control_characters():
    # Newlines and tabs collapse to a single space; NUL is dropped outright, so
    # "and\x00null" joins up rather than gaining a space.
    assert clean_text("line\nbreak\tand\x00null") == "line break andnull"
    assert clean_text("x" * 50, 10) == "x" * 10


def test_strip_formatting_produces_plain_text():
    plain = strip_formatting("## Title\n\n**bold** [link](https://example.com)")
    assert "<" not in plain and "**" not in plain
    assert "Title" in plain and "bold" in plain and "link" in plain


# ---------------------------------------------------------------------------
# End to end: through the forms, into the database, back out of a page
# ---------------------------------------------------------------------------

def _write(client, title: str, body: str):
    return client.post("/write", {
        "title": title,
        "category": "Technology",
        "content": body,
        "summary": "",
        "tags": "",
        "action": "publish",
    })


@pytest.mark.parametrize("payload", XSS_PAYLOADS[:6])
def test_stored_payload_in_a_post_body_renders_inert(auth_client, payload):
    body = f"Here is some text.\n\n{payload}\n\nAnd more text after it."
    response = _write(auth_client, f"Post about {payload[:20]}", body)
    assert response.status_code == 303

    page = auth_client.follow(response)
    assert page.status_code == 200
    # The surrounding prose proves the body really was stored and rendered, so
    # the assertion below is not passing merely because the post is missing.
    assert "And more text after it." in page.text
    # The payload is nowhere in the page as markup — only as escaped text.
    assert payload not in page.text
    assert "&lt;" in page.text


def test_stored_payload_in_a_post_title_renders_inert(auth_client):
    response = _write(
        auth_client,
        '<script>alert("title")</script>',
        "A body long enough to pass validation checks.",
    )
    # Either the title was rejected or it was stored escaped — never rendered.
    if response.status_code == 303:
        page = auth_client.follow(response)
        assert '<script>alert("title")</script>' not in page.text


def test_stored_payload_in_a_comment_renders_inert(auth_client, db):
    post = BlogPost(
        slug="comment-sanitisation-target",
        title="Comment sanitisation target",
        author="Someone",
        category="Technology",
        summary="",
        content="A post that will receive a nasty comment.",
        reading_time=1,
    )
    post.apply_state(POST_PUBLISHED)
    db.add(post)
    db.commit()

    payload = "<img src=x onerror=alert('stored')>"
    response = auth_client.post(f"/blog/{post.slug}/comment", {"body": payload})
    assert response.status_code == 303

    page = auth_client.get(f"/blog/{post.slug}")
    assert page.status_code == 200
    assert payload not in page.text
    # The comment is still there, as text.
    assert "&lt;img" in page.text or "&amp;lt;img" in page.text


def test_profile_fields_are_not_rendered_as_markup(auth_client, user):
    name_payload = "<script>alert('name')</script>"
    bio_payload = "<img src=x onerror=alert('bio')>"
    response = auth_client.post("/profile/edit", {
        "display_name": name_payload,
        "bio": bio_payload,
        "website": "javascript:alert('site')",
    })
    assert response.status_code in (200, 303, 400)

    page = auth_client.get(f"/u/{user.username}")
    if page.status_code == 200:
        assert name_payload not in page.text
        assert bio_payload not in page.text
        assert 'href="javascript:' not in page.text.lower()
