"""Homepage product identity: the home page must present SentientAI
as a cybersecurity product, not a generic writing community.

The blog is preserved as a section (featured/latest posts, categories,
sidebar), but the hero, preview, and capabilities above it must be
security-focused, link to real routes, and never invent metrics,
threat counts, or capabilities.
"""

from tests.conftest import _make_user


def test_homepage_is_product_hero_not_community_hero(client):
    html = client.get("/").text
    assert "Turn security logs into threat intelligence." in html
    assert "MITRE ATT&CK" in html
    assert 'href="/sentinel"' in html
    assert "Analysis preview" in html
    assert "A place for ideas worth reading." not in html
    assert "Start reading — free" not in html
    assert "A community for writers, thinkers, and builders" not in html


def test_homepage_preview_is_labeled_example_not_live_data(client):
    html = client.get("/").text
    assert "Example — not a live detection" in html
    assert "T1505.003" in html
    assert "Unreviewed" in html
    assert "threats blocked" not in html
    assert "attacks stopped" not in html


def test_homepage_capabilities_link_to_real_routes(client):
    html = client.get("/").text
    assert 'id="capabilities"' in html
    assert "Automation Center" in html
    assert "Human-reviewed training" in html
    assert "Desktop Security Lab" in html
    assert 'href="/explore"' in html


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
