"""
S-UX/2.0: the scoped response is lean, and the envelope is the opt-in.

This reverses the rule the code stated for two versions, and the reversal is the
whole change, so what is worth testing is the edges around it rather than the
happy path the other files already cover.

Why now and not later: the envelope repeats, on every response, four things the
caller already has. The @context, the protocol banner the manifest stated, the
URL just requested, and the schema.org host on every enum value. 2.1x the bytes
for identical facts, paid in input tokens on every question. Keeping it as the
default was right while there were agents built against it, and the packages had
been public for hours with essentially none, so this is the cheapest the change
will ever be. Waiting for usage data meant waiting for the people it would break.
"""
from __future__ import annotations

import pytest

from ubag.scoped import manifest, shape_payload

PAYLOAD = {
    "ubag:source": "https://shop.example.com/p/3391",
    "structured_data": [{
        "@type": "Product", "name": "Manteau laine",
        "offers": {"@type": "Offer", "price": "862.00", "priceCurrency": "EUR",
                   "availability": "https://schema.org/InStock"},
    }],
    "text_content": "a very long page of prose " * 50,
}


def body(control):
    return shape_payload(PAYLOAD, control)[0]


def mode(control):
    return shape_payload(PAYLOAD, control)[1]


# ---------------------------------------------------------------------------
# The new default.
# ---------------------------------------------------------------------------

def test_a_scoped_request_is_lean_without_asking():
    out = body({"ubag.fields": "offers.availability"})
    assert out["offers.availability"] == "in stock"
    for gone in ("@context", "ubag:protocol", "url"):
        assert gone not in out


def test_the_subject_is_not_envelope_and_stays():
    """
    {"offers.price": "862.00"} is correct and unusable: an agent that asked what
    a named product costs cannot tell whether this price belongs to it. A url
    identifies, it does not describe.
    """
    assert body({"ubag.fields": "offers.price"})["name"] == "Manteau laine"


def test_unresolved_is_not_envelope_either():
    """
    The distinction lean must never save bytes on. "This resource says nothing
    about calories" and "the calories are nothing" are different answers.
    """
    assert body({"ubag.fields": "calories"})["ubag:unresolved"] == ["calories"]


# ---------------------------------------------------------------------------
# The way back.
# ---------------------------------------------------------------------------

def test_envelope_restores_the_old_shape_verbatim():
    out = body({"ubag.fields": "offers.availability", "ubag": "envelope"})
    assert out["@context"] == "https://schema.org"
    assert out["url"] == "https://shop.example.com/p/3391"
    assert out["offers.availability"] == "https://schema.org/InStock"


def test_envelope_is_reported_in_the_mode():
    assert mode({"ubag.fields": "offers.price"}) == "scoped"
    assert mode({"ubag.fields": "offers.price", "ubag": "envelope"}) == "scoped-envelope"


@pytest.mark.parametrize("control,expected", [
    ({"ubag.fields": "price", "ubag.profile": "auto"}, "auto"),
    ({"ubag.fields": "price", "ubag.profile": "auto", "ubag": "envelope"}, "auto-envelope"),
    ({"ubag.profile": "price"}, "profile"),
    ({"ubag.profile": "price", "ubag": "envelope"}, "profile-envelope"),
])
def test_the_suffix_names_the_exception_not_the_rule(control, expected):
    """
    Modes used to read "lean" and "auto-lean" because lean was the unusual half.
    It is the ordinary half now, so the label marks the envelope instead. A log
    line saying "auto" should mean the normal thing happened.
    """
    assert mode(control) == expected


# ---------------------------------------------------------------------------
# Compatibility, which is most of the risk.
# ---------------------------------------------------------------------------

def test_ubag_lean_still_works_and_is_now_a_no_op():
    """Anyone who wrote it against S-UX/1.1 gets exactly what they asked for."""
    assert body({"ubag.fields": "offers.availability", "ubag": "lean"}) == \
        body({"ubag.fields": "offers.availability"})


def test_an_unrecognised_value_leans_rather_than_reverting():
    """
    A typo must not silently opt somebody back into the old shape, because that
    failure is invisible: the response is valid, just larger, and nothing says
    the parameter was ignored.
    """
    assert "@context" not in body({"ubag.fields": "offers.price", "ubag": "envelop"})
    assert "@context" not in body({"ubag.fields": "offers.price", "ubag": "ENVELOPE!"})


def test_envelope_is_matched_case_insensitively_and_trimmed():
    for spelling in ("envelope", "ENVELOPE", " Envelope "):
        assert "@context" in body({"ubag.fields": "offers.price", "ubag": spelling})


def test_ubag_full_still_means_the_entire_payload():
    """
    The reason the opt-out is not spelled ?ubag=full. That already meant
    something else, and quietly redefining it would have broken the one
    parameter the manifest has advertised since S-UX/1.0.
    """
    out, m = shape_payload(PAYLOAD, {"ubag": "full"})
    assert m == "full"
    assert "text_content" in out


def test_no_parameters_at_all_is_unchanged():
    """Only the scoped shape moved. A plain request still gets the whole page."""
    out, m = shape_payload(PAYLOAD, {})
    assert m == "full"
    assert out is PAYLOAD


# ---------------------------------------------------------------------------
# Discoverability, since the lean body carries no version banner.
# ---------------------------------------------------------------------------

def test_the_manifest_carries_the_version_the_body_no_longer_does():
    m = manifest(PAYLOAD)
    assert m["ubag:protocol"] == "S-UX/2.0"
    assert m["ubag:envelope"] == "?ubag=envelope"
    assert m["ubag:full_payload"] == "?ubag=full"


def test_the_lean_body_deliberately_has_no_version():
    """
    Which is the point, and the reason the manifest has to name it. A banner
    repeated on every response is the envelope's whole problem in miniature.
    """
    assert "ubag:protocol" not in body({"ubag.fields": "offers.price"})
