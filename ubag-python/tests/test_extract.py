"""Tier 1 extraction + envelope tests — harvest declared structured data."""
from ubag._extract import extract_structured_data
from ubag._sux import build_jsonld_response


PAGE_WITH_JSONLD = """
<!doctype html>
<html lang="en">
<head>
  <title>Blue Widget — Acme</title>
  <meta name="description" content="A blue widget.">
  <meta property="og:title" content="Blue Widget">
  <meta property="og:type" content="product">
  <link rel="canonical" href="https://acme.com/widgets/blue">
  <script type="application/ld+json">
  {"@context":"https://schema.org","@type":"Product","name":"Blue Widget","offers":{"@type":"Offer","price":"19.99","priceCurrency":"USD"}}
  </script>
</head>
<body><h1>Blue Widget</h1></body>
</html>
"""

PAGE_OG_ONLY = """
<html>
<head>
  <meta property="og:site_name" content="Acme Store">
  <meta property="og:title" content="Acme Home">
  <meta property="og:description" content="We sell widgets.">
  <meta property="og:type" content="website">
  <meta property="og:image" content="https://acme.com/logo.png">
</head><body></body></html>
"""

PAGE_BARE = """
<html><head><title>Contact Us</title>
<meta name="description" content="Reach the Acme team."></head><body></body></html>
"""

PAGE_GRAPH = """
<html><head><script type="application/ld+json">
{"@context":"https://schema.org","@graph":[
  {"@type":"Organization","name":"Acme"},
  {"@type":"WebSite","name":"Acme Site"}]}
</script></head><body></body></html>
"""

PAGE_MALFORMED_LDJSON = """
<html><head>
<script type="application/ld+json">{ this is not valid json ,,, }</script>
<title>Still Works</title>
</head><body></body></html>
"""


# ── pure extraction ───────────────────────────────────────────────────────────

def test_extracts_jsonld_verbatim():
    d = extract_structured_data(PAGE_WITH_JSONLD)
    assert len(d["jsonld"]) == 1
    node = d["jsonld"][0]
    assert node["@type"] == "Product"
    assert node["offers"]["price"] == "19.99"   # preserved verbatim, not flattened
    assert d["canonical"] == "https://acme.com/widgets/blue"
    assert d["lang"] == "en"
    assert d["title"] == "Blue Widget — Acme"


def test_extracts_opengraph():
    d = extract_structured_data(PAGE_OG_ONLY)
    assert d["og"]["site_name"] == "Acme Store"
    assert d["og"]["type"] == "website"
    assert d["og"]["image"] == "https://acme.com/logo.png"
    assert d["jsonld"] == []


def test_bare_page_yields_title_and_description():
    d = extract_structured_data(PAGE_BARE)
    assert d["title"] == "Contact Us"
    assert d["meta"]["description"] == "Reach the Acme team."


def test_graph_is_flattened_to_nodes():
    d = extract_structured_data(PAGE_GRAPH)
    types = sorted(n["@type"] for n in d["jsonld"])
    assert types == ["Organization", "WebSite"]


def test_malformed_jsonld_is_skipped_not_raised():
    d = extract_structured_data(PAGE_MALFORMED_LDJSON)
    assert d["jsonld"] == []          # bad block dropped
    assert d["title"] == "Still Works"  # rest of the page still parsed


def test_empty_html_is_safe():
    d = extract_structured_data("")
    assert d["jsonld"] == [] and d["title"] is None


# ── envelope assembly + provenance ────────────────────────────────────────────

def test_envelope_passes_jsonld_through_and_marks_declared():
    payload = build_jsonld_response(
        host="acme.com", path="/widgets/blue", site_meta={},
        agent_claims={"sub": "ubag:a1"}, html=PAGE_WITH_JSONLD,
    )
    assert payload["@type"] == "Product"
    assert payload["url"] == "https://acme.com/widgets/blue"   # from canonical
    assert payload["inLanguage"] == "en"
    assert "ubag:declared" in payload and payload["ubag:declared"][0]["@type"] == "Product"
    assert payload["ubag:provenance"]["confidence"] == "declared"
    assert "json-ld" in payload["ubag:provenance"]["sources"]
    assert payload["ubag:agent"] == "ubag:a1"


def test_opengraph_maps_into_envelope():
    payload = build_jsonld_response(
        host="acme.com", path="/", site_meta={},
        agent_claims={}, html=PAGE_OG_ONLY,
    )
    assert payload["@type"] == "WebSite"          # og:type website
    assert payload["name"] == "Acme Home"         # og:title
    assert payload["description"] == "We sell widgets."
    assert payload["image"] == "https://acme.com/logo.png"
    assert "opengraph" in payload["ubag:provenance"]["sources"]


def test_site_meta_overrides_extracted():
    payload = build_jsonld_response(
        host="acme.com", path="/widgets/blue",
        site_meta={"name": "Owner Override", "type": "Store"},
        agent_claims={}, html=PAGE_WITH_JSONLD,
    )
    assert payload["name"] == "Owner Override"     # site_meta wins over og/jsonld
    assert payload["@type"] == "Store"             # site_meta type wins
    assert payload["ubag:provenance"]["fields_from_site_meta"] == ["name"]
    assert "site_meta" in payload["ubag:provenance"]["sources"]


def test_backward_compatible_without_html():
    # No html → original site_meta-only behavior, no declared block.
    payload = build_jsonld_response(
        host="acme.com", path="/", site_meta={"name": "Acme", "type": "Store"},
        agent_claims={"sub": "ubag:a1"},
    )
    assert payload["@type"] == "Store"
    assert payload["name"] == "Acme"
    assert payload["ubag:branch"] == "B-AGENT"
    assert "ubag:declared" not in payload
