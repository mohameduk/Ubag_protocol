"""
Branch B — Structured UX (S-UX) response builder.

Assembles the JSON-LD envelope an authorized agent receives. In one request the
agent gets the site's declared structured data instead of scraping many pages.

Confidence model (Tier 1): everything served here is owner-declared — parsed
JSON-LD, OpenGraph, and meta tags the site already publishes. Nothing is
inferred. `ubag:provenance` records where each part came from so an agent (or
the gateway) can decide how much to trust it. Inferred content (a future
Markdown layer) will be labeled separately and never mixed into the typed
fields.
"""
from __future__ import annotations

import time
from typing import Any

from ubag._extract import extract_structured_data, og_type_to_schema
from ubag._markdown import html_to_markdown


def build_jsonld_response(
    host: str,
    path: str,
    site_meta: dict[str, Any],
    agent_claims: dict,
    html: str | None = None,
    include_markdown: bool = False,
    content_max_chars: int | None = 20000,
) -> dict:
    """
    Build a JSON-LD structured-data response for Branch B agents.

    Args:
        host:         The requesting host (e.g. "example.com")
        path:         The requested path (e.g. "/products/widget")
        site_meta:    Developer-supplied metadata dict. Always wins over anything
                      auto-extracted, so it is both an override and an escape
                      hatch for declaring data the page does not expose.
        agent_claims: Decoded credential claims.
        html:         Optional page HTML. When provided, declared structured data
                      is harvested from it (Tier 1) and merged under site_meta.

    Returns a JSON-LD-compliant dict ready to serialize. Backward compatible:
    with `html=None` this behaves exactly like the original site_meta wrapper.
    """
    now = int(time.time())
    site_meta = site_meta or {}
    sources: list[str] = []

    base: dict[str, Any] = {
        "@context": "https://schema.org",
        "@type": "WebSite",
        "url": f"https://{host}{path}",
        "name": host,
    }

    declared_nodes: list[dict] = []

    # ── Auto-harvest declared data (Tier 1) ───────────────────────────────────
    if html:
        data = extract_structured_data(html)

        # OpenGraph / meta — normalized convenience fields (owner-declared).
        og = data["og"]
        if og:
            sources.append("opengraph")
        elif data["meta"] or data["title"]:
            sources.append("meta")
        schema_type = og_type_to_schema(og.get("type"))
        if schema_type:
            base["@type"] = schema_type
        if data["title"]:
            base["name"] = data["title"]
        desc = og.get("description") or data["meta"].get("description")
        if desc:
            base["description"] = desc
        if og.get("image"):
            base["image"] = og["image"]
        if data["canonical"]:
            base["url"] = data["canonical"]
        if data["lang"]:
            base["inLanguage"] = data["lang"]

        # Raw JSON-LD nodes — passed through verbatim, highest fidelity.
        declared_nodes = data["jsonld"]
        if declared_nodes:
            sources.append("json-ld")
            primary = declared_nodes[0]
            for key in ("@type", "name", "description", "url", "image"):
                if key in primary and isinstance(primary[key], (str, int, float, bool)):
                    base[key] = primary[key]

    # ── Owner overrides always win ────────────────────────────────────────────
    site_fields: list[str] = []
    for key, value in site_meta.items():
        if key == "type":
            base["@type"] = value
        else:
            base[key] = value
            site_fields.append(key)
    if site_meta:
        sources.append("site_meta")

    # ── Inferred content layer (labeled, never mixed into typed fields) ───────
    has_markdown = False
    if html and include_markdown:
        markdown = html_to_markdown(html, max_chars=content_max_chars)
        if markdown:
            has_markdown = True
            # Deliberately namespaced and marked source=extracted so an agent
            # (or the gateway) can tell this apart from declared, typed data and
            # treat it as advisory prose, not verified facts.
            base["ubag:content"] = {
                "format": "markdown",
                "source": "extracted",
                "text": markdown,
            }
            sources.append("content-markdown")

    # ── UBAG envelope + provenance ────────────────────────────────────────────
    base["ubag:source"] = f"https://{host}"
    base["ubag:served_at"] = now
    base["ubag:agent"] = agent_claims.get("sub", "unknown")
    base["ubag:branch"] = "B-AGENT"
    if declared_nodes:
        base["ubag:declared"] = declared_nodes

    # confidence: declared typed data is always owner-declared; the markdown
    # content is inferred/extracted. "mixed" when both are present.
    declared_present = bool(declared_nodes) or "opengraph" in sources or bool(site_fields)
    if has_markdown:
        confidence = "mixed" if declared_present else "extracted"
    else:
        confidence = "declared"
    base["ubag:provenance"] = {
        "confidence": confidence,
        "sources": sorted(set(sources)),
        "fields_from_site_meta": sorted(site_fields),
    }

    return base
