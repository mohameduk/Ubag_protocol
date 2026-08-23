"""
Scoped retrieval: return the answer, not the page.

This is the half of UBAG that is free and meant to be everywhere. Any site can
implement it without us, and should: the value of an agent identity grows with
the number of sites that answer one, so a scoped endpoint locked to a single
vendor would be worth nothing to anybody.

The cost argument in one line. An agent asking a page what something costs
receives the whole page today, because the page has no way to answer a
narrower question. Measured live against two providers on 63 ground-truth
questions:

    fetch and extract the page   2,695 input tokens   41/63 correct
    ask for the fields             215 input tokens   41/63 correct

12.5x on gpt-4o-mini, 12.1x on gemini-2.5-flash, with accuracy unchanged.

Two rules make this safe to build on, and both are load-bearing:

1. NO MODEL RUNS HERE. Resolution is deterministic lookup over the publisher's
   own structured data. An endpoint that interpreted natural language would
   move the caller's inference cost onto the publisher's server, which is the
   cost this exists to remove.

2. MISSES ARE REPORTED, NEVER GUESSED. A field that cannot be resolved comes
   back in ubag:unresolved. An agent must be able to tell "this resource says
   nothing about price" from "the price is nothing", and a retrieval layer
   that blurs those two starts returning confident wrong answers.

Wire format, on the resource's own URL:

    ?ubag.fields=offers.price,offers.availability   only those typed fields
    ?ubag.manifest=1                                what this resource answers
    ?ubag=compact                                   full facts, less duplication
"""
from __future__ import annotations

from typing import Any, Iterator
from urllib.parse import parse_qsl, urlencode

__all__ = [
    "index_fields", "manifest", "resolve", "parse_fields",
    "split_ubag_query", "shape_payload",
]

# schema.org containers that hold the interesting leaves one level down.
_TRANSPARENT = ("@graph", "itemListElement", "mainEntity", "mainEntityOfPage")

MAX_FIELDS = 32          # per request, so a caller cannot ask for everything
MAX_VALUE_CHARS = 2000   # a leaf longer than this is a document, not a fact


def _walk(node: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    """Yield (dotted_path, value), collapsing lists."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key.startswith("@") and key not in ("@type", "@id"):
                if key in _TRANSPARENT:
                    yield from _walk(value, prefix)
                continue
            path = f"{prefix}.{key}" if prefix else key
            if key in _TRANSPARENT:
                yield from _walk(value, prefix)
            else:
                yield path, value
                yield from _walk(value, path)
    elif isinstance(node, list):
        # No path segment. An agent asking for offers.price should not have to
        # know it is offers[0].price.
        for item in node:
            yield from _walk(item, prefix)


def _walk_indexed(node: Any, prefix: str = "") -> Iterator[tuple[str, Any]]:
    """Like _walk, but list position is part of the path."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key.startswith("@") and key not in ("@type", "@id"):
                if key in _TRANSPARENT:
                    yield from _walk_indexed(value, prefix)
                continue
            path = f"{prefix}.{key}" if prefix else key
            if key in _TRANSPARENT:
                yield from _walk_indexed(value, prefix)
            else:
                yield path, value
                yield from _walk_indexed(value, path)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            yield from _walk_indexed(item, f"{prefix}[{i}]")


def _is_leaf(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) or value is None


def _keep(value: Any) -> bool:
    if not _is_leaf(value):
        return False
    return not (isinstance(value, str) and len(value) > MAX_VALUE_CHARS)


def index_fields(payload: dict) -> dict[str, Any]:
    """
    Build path -> value over the parts of a payload carrying typed facts.

    Publisher-declared structured data is searched first and wins ties. It is
    the site's own assertion about itself, and the only part of a page that was
    authored to be machine-read.
    """
    idx: dict[str, Any] = {}
    for source in (payload.get("structured_data") or [], payload.get("meta") or {}):
        for path, value in _walk(source):
            if not _keep(value):
                continue
            lowered = path.lower()
            idx.setdefault(lowered, value)
            # Index the bare leaf too, so "price" finds "offers.price".
            idx.setdefault(lowered.rsplit(".", 1)[-1], value)
    return idx


def manifest(payload: dict) -> dict:
    """
    What this resource can answer, without answering anything.

    Cheap enough to fetch speculatively and cacheable per URL, so discovery is
    paid once and reused across every later question about the page.
    """
    idx = index_fields(payload)
    types = sorted({
        str(v) for p, v in _walk(payload.get("structured_data") or [])
        if p.lower().endswith("@type") and isinstance(v, str)
    })
    return {
        "@context": "https://schema.org",
        "ubag:protocol": "S-UX/1.1",
        "url": payload.get("ubag:source", ""),
        "ubag:types": types,
        "ubag:fields": sorted(idx),
        "ubag:full_payload": "?ubag=full",
    }


def _positional_index(payload: dict) -> dict[str, Any]:
    """Built on demand, so ordinary requests never pay for it."""
    idx: dict[str, Any] = {}
    # Each JSON-LD block is walked separately, or a caller would have to write
    # [0].openingHoursSpecification[1] and know how many script tags a page has.
    sources = list(payload.get("structured_data") or [])
    sources.append(payload.get("meta") or {})
    for source in sources:
        for path, value in _walk_indexed(source):
            if _keep(value):
                idx.setdefault(path.lower(), value)
    return idx


def resolve(payload: dict, fields: list[str]) -> dict:
    """
    Return only the requested typed fields, plus the subject they belong to.
    """
    idx = index_fields(payload)
    out: dict[str, Any] = {
        "@context": "https://schema.org",
        "ubag:protocol": "S-UX/1.1",
        "url": payload.get("ubag:source", ""),
    }

    # Always name the subject, even when nobody asked.
    #
    # {"offers.price": "862.00"} is correct and unusable: an agent asked what a
    # named product costs cannot tell whether this price belongs to it.
    # Observed directly, a model handed exactly that answered NOT PRESENT
    # rather than risk attributing a price to the wrong item. That instinct is
    # right; the omission was ours. A url identifies, it does not describe.
    subject = idx.get("name") or idx.get("headline") or idx.get("title")
    if isinstance(subject, str) and subject:
        out["name"] = subject

    unresolved: list[str] = []
    positional: dict[str, Any] | None = None

    for raw in fields[:MAX_FIELDS]:
        name = raw.strip()
        if not name:
            continue
        key = name.lower()

        if "[" in key:
            if positional is None:
                positional = _positional_index(payload)
            if key in positional:
                out[name] = positional[key]
            else:
                unresolved.append(name)
            continue

        if key in idx:
            out[name] = idx[key]
            continue
        hit = next((v for p, v in idx.items()
                    if p.endswith("." + key) or p == key), None)
        if hit is not None:
            out[name] = hit
        else:
            unresolved.append(name)

    if unresolved:
        out["ubag:unresolved"] = unresolved
        out["ubag:full_payload"] = "?ubag=full"
    return out


def parse_fields(value: str) -> list[str]:
    """Parse the ubag.fields query parameter."""
    return [f for f in (p.strip() for p in value.split(",")) if f]


def split_ubag_query(query: str) -> tuple[dict[str, str], str]:
    """
    Separate UBAG control parameters from the origin's own query string.

    Control parameters must not reach the origin: forwarding ?ubag.fields=
    upstream is at best ignored and at worst poisons a cache key.
    """
    control: dict[str, str] = {}
    passthrough: list[tuple[str, str]] = []
    for key, value in parse_qsl(query, keep_blank_values=True):
        if key == "ubag" or key.startswith("ubag."):
            control[key] = value
        else:
            passthrough.append((key, value))
    return control, urlencode(passthrough)


def shape_payload(payload: dict, control: dict[str, str]) -> tuple[dict, str]:
    """
    Choose the representation. Returns (body, mode).

    The no-parameter response is the unchanged full payload. Every addition is
    opt-in, because changing the default would alter the response shape for
    agents already built against the published format.
    """
    if "ubag.manifest" in control:
        return manifest(payload), "manifest"
    if "ubag.fields" in control:
        return resolve(payload, parse_fields(control["ubag.fields"])), "scoped"
    if control.get("ubag") == "compact":
        from ._compact import compact
        return compact(payload), "compact"
    # Unrecognised values fall through rather than erroring. A caller sending a
    # mode we do not have should still get a usable page.
    return payload, "full"
