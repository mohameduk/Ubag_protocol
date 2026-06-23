"""
Branch B — Structured UX (S-UX) response builder.

Transforms site metadata into a clean JSON-LD payload for authorized agents.
Agents get structured data in one request instead of scraping 50 pages.
"""
from __future__ import annotations

import time
from typing import Any, Optional


def build_jsonld_response(
    host: str,
    path: str,
    site_meta: dict[str, Any],
    agent_claims: dict,
) -> dict:
    """
    Build a JSON-LD structured data response for Branch B agents.

    Args:
        host:        The requesting host (e.g. "example.com")
        path:        The requested path (e.g. "/products/widget")
        site_meta:   Developer-supplied metadata dict (see UBAGMiddleware.site_meta)
        agent_claims: Decoded credential claims

    Returns a JSON-LD compliant dict ready to serialize.
    """
    now = int(time.time())

    base = {
        "@context": "https://schema.org",
        "@type": site_meta.get("type", "WebSite"),
        "url": f"https://{host}{path}",
        "name": site_meta.get("name", host),
        "ubag:source": f"https://{host}",
        "ubag:served_at": now,
        "ubag:agent": agent_claims.get("sub", "unknown"),
        "ubag:branch": "B-AGENT",
    }

    # Merge any developer-supplied schema.org fields
    for key, value in site_meta.items():
        if key not in ("type",):
            base[key] = value

    return base
