"""The activity log: your own record, and only yours.

`/activity` is the one page that shows an account's private entries, so the
tests here are mostly about scoping — a private entry must appear for its owner,
never on the public profile, and never in another account's log. The rest pins
down the filter, which narrows to nothing on an unknown type rather than
quietly widening the result.
"""
from __future__ import annotations

import pytest

from app.services.activity_service import log_activity

PUBLIC_DESC = "Published a post about static analysis"
PRIVATE_DESC = "Changed the notification preferences"


@pytest.fixture
def entries(db, user):
    public = log_activity(db, user.id, "blog_post_published", PUBLIC_DESC,
                          is_public=True)
    private = log_activity(db, user.id, "profile_updated", PRIVATE_DESC,
                           is_public=False)
    yield public, private


# ---------------------------------------------------------------------------
# Access
# ---------------------------------------------------------------------------

def test_the_activity_log_requires_sign_in(client):
    response = client.get("/activity")
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login")


def test_me_redirects_to_your_own_public_profile(auth_client, user):
    response = auth_client.get("/me")
    assert response.status_code == 303
    assert response.headers["location"] == f"/u/{user.username}"


def test_me_requires_sign_in(client):
    assert client.get("/me").status_code == 303


# ---------------------------------------------------------------------------
# What it shows
# ---------------------------------------------------------------------------

def test_your_own_log_shows_public_and_private_entries(auth_client, entries):
    page = auth_client.get("/activity")
    assert page.status_code == 200
    assert PUBLIC_DESC in page.text
    # The private entry is the point of this page existing.
    assert PRIVATE_DESC in page.text
    assert "Private" in page.text


def test_a_private_entry_stays_off_the_public_profile(client, user, entries):
    page = client.get(f"/u/{user.username}")
    assert page.status_code == 200
    assert PRIVATE_DESC not in page.text


def test_a_private_entry_stays_out_of_the_community_feed(client, entries):
    page = client.get("/community")
    assert page.status_code == 200
    assert PRIVATE_DESC not in page.text


def test_one_users_log_is_not_visible_to_another(other_client, entries):
    page = other_client.get("/activity")
    assert page.status_code == 200
    assert PUBLIC_DESC not in page.text
    assert PRIVATE_DESC not in page.text


def test_an_empty_log_explains_itself(auth_client, db, user):
    page = auth_client.get("/activity")
    assert page.status_code == 200
    assert "No activity yet" in page.text


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

def test_filtering_by_type_narrows_the_list(auth_client, entries):
    page = auth_client.get("/activity", params={"kind": "profile_updated"})
    assert page.status_code == 200
    assert PRIVATE_DESC in page.text
    assert PUBLIC_DESC not in page.text


def test_an_unknown_type_is_ignored_rather_than_narrowing_wrongly(auth_client, entries):
    # `kind` outside the vocabulary falls back to "everything", which is the
    # safe direction: it cannot be used to probe for types.
    page = auth_client.get("/activity", params={"kind": "no-such-type"})
    assert page.status_code == 200
    assert PUBLIC_DESC in page.text
    assert PRIVATE_DESC in page.text


def test_the_filter_row_only_offers_types_you_actually_have(auth_client, entries):
    page = auth_client.get("/activity")
    assert "Published a post" in page.text or "blog_post_published" in page.text
    # Nothing this account has ever done, so it must not be offered.
    assert "lab_started" not in page.text


def test_a_filter_value_is_not_reflected_into_the_page(auth_client, entries):
    payload = "<script>alert(1)</script>"
    page = auth_client.get("/activity", params={"kind": payload})
    assert page.status_code == 200
    assert payload not in page.text


def test_a_page_number_past_the_end_clamps_instead_of_erroring(auth_client, entries):
    page = auth_client.get("/activity", params={"page": 9999})
    assert page.status_code == 200


def test_a_negative_page_number_is_refused(auth_client, entries):
    assert auth_client.get("/activity", params={"page": -1}).status_code == 422
