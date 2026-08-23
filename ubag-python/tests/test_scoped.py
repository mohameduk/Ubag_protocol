"""
Scoped retrieval regressions.

Two of these pin bugs that shipped in v0.5.0 and were found by reading live
payloads rather than by any test: the subject anchor naming a nested author,
and scalar arrays being unreachable through both walkers.
"""
from __future__ import annotations

from ubag.scoped import resolve, shape_payload

# ---------------------------------------------------------------------------
# Two bugs that shipped in v0.5.0
# ---------------------------------------------------------------------------

ARTICLE = {
    "ubag:source": "https://example.com/journal/gestes.html",
    "structured_data": [{
        "@context": "https://schema.org",
        "@type": "NewsArticle",
        "headline": "Les gestes de la main",
        "wordCount": "42160",
        "author": {"@type": "Person", "name": "Leila Ben Youssef"},
        "publisher": {"@type": "Organization", "name": "Maison Fathia"},
    }],
    "meta": {},
}

STORE = {
    "ubag:source": "https://example.com/",
    "structured_data": [{
        "@type": "Store", "name": "Maison Fathia",
        "openingHoursSpecification": [
            {"@type": "OpeningHoursSpecification",
             "dayOfWeek": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
             "opens": "09:30", "closes": "18:30"},
            {"@type": "OpeningHoursSpecification", "dayOfWeek": "Saturday",
             "opens": "10:00", "closes": "17:00"},
        ],
    }],
    "meta": {},
}


def test_the_anchor_names_the_article_not_its_author():
    """
    The index is flattened, so the bare key "name" was filled from author.name
    and every article told agents its subject was a person. Handed
    {"name": "Leila Ben Youssef", "wordCount": "42160"} and asked for the
    edition length, a model answered NOT PRESENT. Correctly: nothing in that
    payload says what has 42,160 words.
    """
    body = resolve(ARTICLE, ["wordCount"])
    assert body["name"] == "Les gestes de la main"
    assert body["wordCount"] == "42160"


def test_a_nested_publisher_is_not_the_subject_either():
    assert resolve(ARTICLE, ["wordCount"])["name"] != "Maison Fathia"


def test_a_list_of_plain_strings_is_reachable():
    # Both walkers only recursed into dicts, so a scalar array emitted nothing.
    # dayOfWeek was unreachable, and with it keywords, sameAs, all of them.
    assert resolve(STORE, ["dayOfWeek"])["dayOfWeek"] == "Monday"


def test_a_specific_element_of_a_scalar_list_is_reachable():
    body = resolve(STORE, ["openingHoursSpecification[0].dayOfWeek[4]"])
    assert body["openingHoursSpecification[0].dayOfWeek[4]"] == "Friday"


def test_auto_needs_no_vertical_knowledge():
    """Nothing in this library knows what a clinic is."""
    clinic = {
        "ubag:source": "https://example.clinic/",
        "structured_data": [{
            "@type": "MedicalClinic", "name": "Hamilton Family Practice",
            "address": {"@type": "PostalAddress", "streetAddress": "120 King St W",
                        "addressLocality": "Hamilton", "addressCountry": "CA"},
        }],
        "meta": {},
    }
    body, mode = shape_payload(clinic, {"ubag.fields": "streetAddress",
                                        "ubag.profile": "auto"})
    assert mode == "auto"
    assert body["address.streetaddress"] == "120 King St W"
    assert body["address.addresscountry"] == "CA"
