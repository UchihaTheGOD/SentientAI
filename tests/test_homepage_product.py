"""Homepage marketing identity: the public home page introduces the
product; it is not the security dashboard.

Since the public/private separation, the homepage must NOT show an
analysis preview, pipeline internals, technique IDs, verdict badges,
or any security record. Those live in the private security workspace
(/sentinel). The homepage keeps marketing copy, capability descriptions
in marketing terms, and the blog section. Signed-in users get a link
to the security dashboard; anonymous visitors get Get started / Sign
in / Explore only — never a security link.
"""

from tests.conftest import _make_user


def test_homepage_is_marketing_not_dashboard(client):
    html = client.get("/").text
    assert "Turn security logs into threat intelligence." in html
    assert "Analysis preview" not in html
    assert "pipeline-steps" not in html
    assert "T1505.003" not in html
    assert "likely_threat" not in html
    assert "How it works" not in html
    assert "threats blocked" not in html
    assert "attacks stopped" not in html
    assert 'href="/sentinel"' not in html
    assert 'href="/register"' in html
    assert 'href="/explore"' in html


def test_homepage_signed_in_links_to_security_dashboard(auth_client):
    html = auth_client.get("/").text
    assert 'href="/sentinel"' in html
    assert "Analysis preview" not in html
    assert "T1505.003" not in html


def test_homepage_admin_sees_automation_link_anonymous_does_not(client):
    anon_html = client.get("/").text
    assert 'href="/admin/automation"' not in anon_html
    admin = _make_user("admin")
    assert client.login(admin.username).status_code == 303
    authed = client.get("/").text
    assert 'href="/admin/automation"' in authed
    assert 'href="/admin/training"' in authed


def test_homepage_keeps_theme_stylesheets_and_blog_section(client):
    html = client.get("/").text
    for sheet in ("nx-tokens.css", "nx-components.css", "nx-layout.css"):
        assert sheet in html
    assert "From the community" in html
    assert "No posts yet" in html
