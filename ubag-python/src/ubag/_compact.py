"""
Compact representation: same facts as the full payload, less duplication.

A full S-UX payload is close to lossless, which is the hard part. What it is
not is cheap, and the cost is almost entirely redundancy rather than
information:

  * text_content restates every heading, every list item and most table cells
    that the structured sections already carry, so the same fact is paid for
    two or three times.
  * meta emits every <meta> tag on the page. viewport, charset, theme-color and
    a full set of twitter: duplicates of the og: values are not facts an agent
    will ever retrieve.
  * links inlines the whole navigation. On a content page that is frequently
    the single largest section, and an agent asking a question about the page
    did not ask where else it could go.

So: emit the typed sections first, then emit only the prose that is NOT already
covered by them. Nothing is thrown away that transform() kept. The saving is
duplication, which means retention should hold while cost falls.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any, Iterable

# Meta keys worth their tokens. Everything else on a real page is rendering
# hints, analytics ids, or twitter: restatements of the og: values.
_META_KEEP = (
    "title", "description",
    "og_title", "og_description", "og_type", "og_url",
    "article_published_time", "article_modified_time",
    "author", "keywords",
)

_WS = re.compile(r"\s+")
# Split prose into candidate units. Sentence-ish, but line breaks matter more
# than punctuation in extracted markdown, so both are boundaries.
_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")


def _norm(s: str) -> str:
    s = unicodedata.normalize("NFKD", s)
    s = "".join(c for c in s if not unicodedata.combining(c))
    return _WS.sub(" ", s).strip().lower()


def _covered_strings(payload: dict) -> set[str]:
    """Every fact the typed sections already carry, normalised for comparison."""
    out: set[str] = set()

    for h in payload.get("headings") or []:
        if isinstance(h, dict) and h.get("text"):
            out.add(_norm(h["text"]))

    for table in payload.get("tables") or []:
        for row in table if isinstance(table, list) else []:
            values = row.values() if isinstance(row, dict) else row
            for v in values:
                if isinstance(v, str) and v.strip():
                    out.add(_norm(v))

    for lst in payload.get("lists") or []:
        for item in lst if isinstance(lst, list) else []:
            if isinstance(item, str) and item.strip():
                out.add(_norm(item))

    meta = payload.get("meta") or {}
    for k in ("title", "description", "og_title", "og_description"):
        if meta.get(k):
            out.add(_norm(str(meta[k])))

    return {s for s in out if len(s) >= 3}


def _residual_prose(text: str, covered: set[str]) -> str:
    """
    Prose minus anything the typed sections already state.

    A unit is dropped when its normalised form is already covered, or when it is
    wholly contained in a covered string. Containment matters because extracted
    markdown often re-emits a heading as a bare line, and a table cell as part
    of a longer sentence.
    """
    if not text:
        return ""
    kept: list[str] = []
    for unit in _SPLIT.split(text):
        u = unit.strip()
        if not u:
            continue
        n = _norm(u)
        if len(n) < 3 or n in covered:
            continue
        if any(n in c for c in covered if len(c) > len(n)):
            continue
        kept.append(u)
    return "\n".join(kept)


def compact(payload: dict, prose: str = "") -> dict:
    """
    Build the agent-facing payload from a transform() result.

    `prose` is the page's running text. Pass transform()'s own text_content, or
    an extractor's markdown if you have one; anything it contains that the typed
    sections already carry is removed either way.
    """
    meta = payload.get("meta") or {}
    out: dict[str, Any] = {
        "@context": "https://schema.org",
        "@type": "WebPage",
        "ubag:protocol": "S-UX/2.0",
        "url": payload.get("ubag:source", ""),
    }

    kept_meta = {k: meta[k] for k in _META_KEEP if meta.get(k)}
    if kept_meta:
        out["meta"] = kept_meta

    # Publisher-declared structured data is already typed and already correct.
    # It is the cheapest true information on any page.
    for key in ("structured_data", "tables", "lists", "forms"):
        if payload.get(key):
            out[key] = payload[key]

    if payload.get("headings"):
        # Levels are rendering detail. The text is the fact.
        out["headings"] = [h["text"] for h in payload["headings"]
                           if isinstance(h, dict) and h.get("text")]

    covered = _covered_strings(payload)
    residue = _residual_prose(prose or payload.get("text_content", ""), covered)
    if residue:
        out["text"] = residue

    # Navigation is advertised, not inlined. An agent that wants it asks.
    links = payload.get("links") or []
    if links:
        out["ubag:links_available"] = len(links)
        out["ubag:links_endpoint"] = "?ubag=links"

    return out


# Measured, so nobody has to rediscover it: compact came in at 0.9x against an
# agent simply extracting the page itself, three separate times. It is offered
# because it belongs in the negotiated set, not because it saves money. The
# cost win lives entirely in scoped retrieval.
