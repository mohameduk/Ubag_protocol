"""
answer(), and making the profiles discoverable.

fields() has always been able to produce the good answer. It just made you ask
for it in three parts, and the two parts nobody adds by hand are the two that
matter: profile=auto so a price arrives with its currency, and lean so the
envelope the manifest already told you is not repeated on every response.

The profiles had the opposite problem. They worked and could not be found: an
agent had to already know the word "hours" to ask for it, and asking a page that
has none produced an unresolved list rather than a signal that the intent does
not apply here.
"""
from __future__ import annotations

import pytest

from ubag import Agent
from ubag.scoped import PROFILES, manifest, shape_payload

PRODUCT = {
    "ubag:source": "https://shop.example.com/p/3391",
    "structured_data": [{
        "@type": "Product",
        "name": "Manteau laine",
        "offers": {"@type": "Offer", "price": "862.00", "priceCurrency": "EUR",
                   "availability": "https://schema.org/InStock"},
    }],
}

CLINIC = {
    "ubag:source": "https://clinic.example.com/",
    "structured_data": [{
        "@type": "MedicalClinic",
        "name": "Clinique Nord",
        "telephone": "+33 1 23 45 67 89",
        "address": {"@type": "PostalAddress", "streetAddress": "12 rue Ney",
                    "addressLocality": "Lyon", "addressCountry": "FR"},
        "openingHoursSpecification": [
            {"@type": "OpeningHoursSpecification", "dayOfWeek": "Monday",
             "opens": "09:00", "closes": "18:00"},
            {"@type": "OpeningHoursSpecification", "dayOfWeek": "Saturday",
             "opens": "10:00", "closes": "13:00"},
        ],
    }],
}


class Recorder(Agent):
    """Captures the query instead of making a request."""

    def __init__(self):
        self.query = None

    def _get(self, url, params):
        self.query = params
        return {"ok": True}


# ---------------------------------------------------------------------------
# answer()
# ---------------------------------------------------------------------------

def test_answer_asks_for_expansion_and_lean_without_being_told():
    a = Recorder()
    a.answer("https://shop.example.com/p/3391", "price")
    assert a.query == "ubag.fields=price&ubag.profile=auto&ubag=lean"


def test_answer_takes_several_fields():
    a = Recorder()
    a.answer("https://x.example/p", "price", "availability")
    assert a.query.startswith("ubag.fields=price,availability&")


def test_fields_is_left_exactly_as_it_was():
    """
    answer() is additive. Callers who want the enveloped form, or the leaf
    without its entity, still have it and their requests are unchanged.
    """
    a = Recorder()
    a.fields("https://x.example/p", ["offers.price"])
    assert a.query == "ubag.fields=offers.price"


def test_what_answer_actually_returns():
    """The query it builds, run through the server side that answers it."""
    body, mode = shape_payload(PRODUCT, {"ubag.fields": "price",
                                         "ubag.profile": "auto", "ubag": "lean"})
    assert mode == "auto-lean"
    # The currency came along, which is the point.
    assert body["offers.price"] == "862.00"
    assert body["offers.priceCurrency"] == "EUR"
    # Keys carry the publisher's casing, so offers.priceCurrency is a name that
    # exists on their page. It used to lowercase to offers.pricecurrency.
    assert "offers.pricecurrency" not in body
    # The enum lost its schema.org host, so a model reads a sentence.
    assert body["offers.availability"] == "in stock"
    # The subject is named, so a price cannot be attributed to the wrong thing.
    assert body["name"] == "Manteau laine"
    # And the envelope is gone.
    assert "@context" not in body and "ubag:protocol" not in body


def test_a_price_alone_is_the_thing_answer_exists_to_prevent():
    """Without expansion you get a number you cannot transact on."""
    body, _ = shape_payload(PRODUCT, {"ubag.fields": "price", "ubag": "lean"})
    assert body["price"] == "862.00"
    assert "priceCurrency" not in body


def test_unresolved_survives_lean():
    """
    "This resource says nothing about price" and "the price is nothing" are
    different answers, and lean must not blur them to save four tokens.
    """
    body, _ = shape_payload(PRODUCT, {"ubag.fields": "calories",
                                      "ubag.profile": "auto", "ubag": "lean"})
    assert body["ubag:unresolved"] == ["calories"]


# ---------------------------------------------------------------------------
# The manifest advertises what this resource can answer.
# ---------------------------------------------------------------------------

def test_a_product_advertises_price_and_not_opening_hours():
    assert manifest(PRODUCT)["ubag:profiles"] == ["price"]


def test_a_clinic_advertises_the_intents_it_can_serve():
    found = manifest(CLINIC)["ubag:profiles"]
    assert "hours" in found and "contact" in found and "address" in found
    assert "price" not in found


def test_a_page_with_nothing_advertises_nothing():
    assert manifest({"structured_data": []})["ubag:profiles"] == []


@pytest.mark.parametrize("name", sorted(PROFILES))
def test_an_advertised_profile_answers_something(name):
    """
    Advertising means the intent applies to this resource, not that every field
    in it is present. A clinic that publishes a street and a city but no postal
    code still answers "address"; the postcode comes back under unresolved,
    which is the rule about misses working rather than failing.

    What must not happen is advertising an intent that answers nothing at all.
    """
    for payload in (PRODUCT, CLINIC):
        if name not in manifest(payload)["ubag:profiles"]:
            continue
        body, mode = shape_payload(payload, {"ubag.profile": name})
        assert mode == "profile"
        answered = [k for k in body
                    if not k.startswith(("@", "ubag:", "url")) and k != "name"]
        assert answered, f"{name} advertised but answered nothing"


@pytest.mark.parametrize("name", sorted(PROFILES))
def test_a_profile_that_is_not_advertised_answers_nothing(name):
    """The other direction, and the one that makes advertising worth reading."""
    for payload in (PRODUCT, CLINIC):
        if name in manifest(payload)["ubag:profiles"]:
            continue
        body, _ = shape_payload(payload, {"ubag.profile": name})
        answered = [k for k in body
                    if not k.startswith(("@", "ubag:", "url")) and k != "name"]
        assert not answered, f"{name} answered despite not being advertised"


def test_the_manifest_still_says_what_it_always_did():
    m = manifest(PRODUCT)
    assert m["ubag:protocol"] == "S-UX/1.1"
    assert "price" in m["ubag:fields"]
    assert m["ubag:full_payload"] == "?ubag=full"


def test_the_profile_vocabulary_is_the_one_both_sdks_ship():
    """
    Ported to Node in the same commit. If a name is added here and not there, a
    Python origin answers a request a Node origin does not, and the promise of
    an identical wire format stops being true.
    """
    assert sorted(PROFILES) == ["address", "contact", "hours", "price", "rating"]
