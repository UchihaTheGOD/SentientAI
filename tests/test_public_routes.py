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


@pytest.mark.parametrize("path", PUBLIC_PAGES)
def test_public_page_uses_no_lab_vocabulary(client, path):
    body = client.get(path).text.lower()
    # Strip the CSP header echo and inline SVG paths, which contain no prose.
    prose = re.sub(r"<svg.*?</svg>", " ", body, flags=re.DOTALL)
    found = [word for word in LAB_VOCABULARY if word in prose]
    assert not found, f"{path} exposes testing-area wording: {found}"


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
