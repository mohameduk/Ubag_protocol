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
    assert body["address.streetAddress"] == "120 King St W"
    assert body["address.addressCountry"] == "CA"


# ---------------------------------------------------------------------------
# Named profiles, for intents that are not structural
# ---------------------------------------------------------------------------

PRODUCT = {
    "ubag:source": "https://example.com/p/1",
    "structured_data": [{
        "@type": "Product", "name": "Manteau 3391", "sku": "MF-M3391",
        "offers": {"@type": "Offer", "price": "689.00", "priceCurrency": "EUR",
                   "availability": "https://schema.org/InStock"},
        "aggregateRating": {"@type": "AggregateRating",
                            "ratingValue": "4.8", "reviewCount": 184},
    }],
    "meta": {},
}


def test_price_profile_binds_the_currency_to_the_amount():
    body, mode = shape_payload(PRODUCT, {"ubag.profile": "price"})
    assert mode == "profile"
    assert body["price"] == "689.00"
    assert body["priceCurrency"] == "EUR"


def test_hours_profile_answers_a_specific_day():
    """
    'What time do you open on Saturday' is unanswerable from an index that
    collapses lists to their first element, which is why hours is a named
    profile rather than left to structural expansion.
    """
    body, _ = shape_payload(STORE, {"ubag.profile": "hours"})
    flat = {k: v for k, v in body.items() if "openingHours" in k}
    assert any(v == "Saturday" for v in flat.values())
    assert any(v == "10:00" for v in flat.values())
    # Publisher casing, and @type is plumbing that answers nothing.
    assert any(k.startswith("openingHoursSpecification[") for k in flat)
    assert not any(k.endswith(".@type") for k in flat)


def test_an_unknown_profile_does_not_claim_the_mode():
    # Falls through to ubag.fields, so a typo cannot look like a page with no
    # data.
    body, mode = shape_payload(PRODUCT, {"ubag.profile": "nonsense",
                                         "ubag.fields": "sku"})
    assert mode == "scoped"
    assert body["sku"] == "MF-M3391"
