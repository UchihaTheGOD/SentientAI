"""The public website: reachable anonymously, and free of lab vocabulary.

Point 1 of the brief is that the public side reads as an ordinary community
site. That is a testable claim, so it is tested here: every public page is
fetched anonymously and scanned for the terminology the testing area uses.
"""
from __future__ import annotations

import re

import pytest

from app.models.blog_post import POST_PUBLISHED, BlogPost

PUBLIC_PAGES = [
    "/",
    "/about",
    "/contact",
    "/blog",
    "/explore",
    "/community",
    "/login",
    "/register",
    "/search?q=hello",
    "/category/Technology",
]

# Words that belong to the private testing area. If one of these reaches a
# public page, the two experiences have bled into each other.
LAB_VOCABULARY = [
    "payload", "penetration test", "exploit", "attack lab",
    "sql injection", "xss", "honeypot", "cyberllm", "sentinel",
    "vulnerability lab", "security testing",
]


@pytest.fixture
def published_post(db):
    post = BlogPost(
        slug="a-perfectly-normal-post",
        title="A perfectly normal post",
        author="Someone",
        category="Technology",
        summary="A short summary.",
        content="This is the body of a normal community post about nothing special.",
        reading_time=1,
    )
    post.apply_state(POST_PUBLISHED)
    db.add(post)
    db.commit()
    db.refresh(post)
    yield post


@pytest.mark.parametrize("path", PUBLIC_PAGES)
def test_public_page_is_reachable_anonymously(client, path):
    response = client.get(path)
    assert response.status_code == 200, f"{path} -> {response.status_code}"


def find_lab_vocabulary(html: str) -> list[str]:
    """LAB_VOCABULARY words present in a page's wording.

    Two things in the raw HTML are not wording and must not trip the
    check. Inline SVG blocks (path data, already stripped by the
    original test) and CSRF token values: a token is random
    base64url, so about 1 in 960 tokens contains the substring
    "xss" by chance, and the form echoes the token verbatim into
    a hidden input. A Windows run failed on exactly that. Stripping
    the token elements keeps the check's intent intact — visible
    text, attributes, links and comments are still scanned, and
    "xss" is NOT removed from the vocabulary list.
    """
    prose = re.sub(r"<svg.*?</svg>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    # Hidden CSRF inputs and csrf-token meta tags carry random values.
    prose = re.sub(r'<input[^>]*name="csrf_token"[^>]*>', " ", prose,
                   flags=re.IGNORECASE)
    prose = re.sub(r'<meta[^>]*name="csrf-token"[^>]*>', " ", prose,
                   flags=re.IGNORECASE)
    lowered = prose.lower()
    return [word for word in LAB_VOCABULARY if word in lowered]


@pytest.mark.parametrize("path", PUBLIC_PAGES)
def test_public_page_uses_no_lab_vocabulary(client, path):
    body = client.get(path).text
    found = find_lab_vocabulary(body)
    assert not found, f"{path} exposes testing-area wording: {found}"


def test_csrf_token_containing_lab_word_is_not_page_wording(client):
    """Regression for the Windows failure: a CSRF token that happens
    to contain "xss" must not trip the vocabulary check, because the
    token is random, not wording. The crafted well-formed token is
    echoed verbatim into the contact form, so the OLD matcher would
    fail this exact response — the assertions below prove the trap
    is genuinely present before asserting the new matcher ignores it.
    """
    from app.services.csrf import _sign

    raw = "AbXssCdEfGh123456"
    token = raw + "." + _sign(raw)
    client._client.cookies.set("csrf_token", token)
    body = client.get("/contact").text
    assert token in body
    assert "xss" in body.lower()
    assert find_lab_vocabulary(body) == []


def test_visible_lab_wording_still_trips_the_check():
    """The token fix must not weaken the check: real wording, and
    wording in attributes, still fails."""
    assert find_lab_vocabulary("<p>Learn about XSS here</p>") == ["xss"]
    assert find_lab_vocabulary("<p>Nothing special here</p>") == []
    assert find_lab_vocabulary(
        '<a href="/x" title="penetration test guide">x</a>'
    ) == ["penetration test"]


@pytest.mark.parametrize("path", PUBLIC_PAGES)
def test_public_page_does_not_link_to_the_testing_area(client, path):
    body = client.get(path).text
    assert 'href="/testing' not in body, f"{path} advertises /testing"


def test_post_page_renders_for_anonymous_readers(client, published_post):
    response = client.get(f"/blog/{published_post.slug}")
    assert response.status_code == 200
    assert published_post.title in response.text


def test_unknown_post_returns_a_404_page(client):
    response = client.get("/blog/no-such-post-exists")
    assert response.status_code == 404


def test_unknown_path_returns_a_404_page(client):
    response = client.get("/definitely-not-a-route")
    assert response.status_code == 404


def test_security_headers_are_present(client):
    headers = client.get("/").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    # No 'unsafe-inline' in script-src: the CSP has to actually stop inline JS
    # for it to be worth anything as a second line of defence behind sanitising.
    script_src = [
        part for part in headers["Content-Security-Policy"].split("; ")
        if part.startswith("script-src")
    ]
    assert script_src and "unsafe-inline" not in script_src[0]


def test_search_reflects_nothing_executable(client):
    payload = '<script>alert(1)</script>'
    response = client.get("/search", params={"q": payload})
    assert response.status_code == 200
    assert "<script>alert(1)</script>" not in response.text


def test_write_page_requires_sign_in(client):
    response = client.get("/write")
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login?next=/write")


def test_authenticated_pages_require_sign_in(client):
    for path in ("/bookmarks", "/notifications", "/my/posts", "/profile/edit",
                 "/dashboard", "/activity", "/me"):
        response = client.get(path)
        assert response.status_code == 303, path
        assert response.headers["location"].startswith("/login"), path
