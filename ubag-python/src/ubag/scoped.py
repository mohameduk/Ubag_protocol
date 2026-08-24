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

import re
from typing import Any, Iterator
from urllib.parse import parse_qsl, urlencode

__all__ = [
    "index_fields", "manifest", "resolve", "parse_fields",
    "split_ubag_query", "shape_payload", "auto_expand", "subject_of",
    "expand_profiles", "PROFILES",
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
            if _is_leaf(item):
                # A list of plain strings used to yield nothing at all. The
                # parent yielded the list, which is not a leaf and was dropped,
                # and this branch only ever descended into dicts. So
                # dayOfWeek: ["Monday", ...] was unreachable, and with it every
                # scalar array: keywords, sameAs, all of them. First element
                # wins the collapsed key, matching how offers.price behaves.
                yield prefix, item
            else:
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
            path = f"{prefix}[{i}]"
            # Same omission as _walk: scalars inside a list were never emitted.
            if _is_leaf(item):
                yield path, item
            else:
                yield from _walk_indexed(item, path)


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


_SUBJECT_KEYS = ("name", "headline", "title")
# Entity types that are page furniture rather than what the page is about.
_NOT_SUBJECT = {"breadcrumblist", "listitem", "website", "searchaction",
                "webpage", "imageobject", "collectionpage",
                "sitenavigationelement"}


def _entities(payload: dict) -> Iterator[dict]:
    """Top-level entities, unwrapping @graph, never descending into values."""
    stack: list[Any] = list(payload.get("structured_data") or [])
    while stack:
        node = stack.pop(0)
        if isinstance(node, list):
            stack[:0] = node
            continue
        if not isinstance(node, dict):
            continue
        graph = node.get("@graph")
        if graph is not None:
            stack[:0] = graph if isinstance(graph, list) else [graph]
            continue
        yield node


def subject_of(payload: dict) -> str | None:
    """
    What this resource is about, from an entity's own top level.

    This used to read index_fields()["name"], and the index is flattened: every
    leaf is stored under its bare name as well as its dotted path. A NewsArticle
    keeps its title in headline and has no top-level name, so the bare "name"
    key was filled from author.name and the anchor announced the subject of
    every article as a person.

    An agent then received {"name": "Leila Ben Youssef", "wordCount": "42160"},
    which describes a human being with a word count, and a model asked for the
    edition length answered NOT PRESENT. Correctly: nothing in that payload says
    what has 42,160 words. The anchor exists to prevent exactly that
    misattribution and was causing it.

    Furniture types are passed over on a first sweep and accepted on a second,
    so a page carrying only a breadcrumb still gets an anchor rather than none.
    """
    entities = list(_entities(payload))

    def pick(skip_furniture: bool) -> str | None:
        for ent in entities:
            declared = ent.get("@type") or ""
            names = {t.lower() for t in
                     (declared if isinstance(declared, list) else [declared])
                     if isinstance(t, str)}
            if skip_furniture and names & _NOT_SUBJECT:
                continue
            for key in _SUBJECT_KEYS:
                value = ent.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        return None

    found = pick(True) or pick(False)
    if found:
        return found
    title = (payload.get("meta") or {}).get("title")
    return title.strip() if isinstance(title, str) and title.strip() else None


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


_SCHEMA_PREFIX = "https://schema.org/"
_ENUM_WORDS = {
    "instock": "in stock", "outofstock": "out of stock",
    "preorder": "pre-order", "presale": "pre-sale", "soldout": "sold out",
    "limitedavailability": "limited availability", "backorder": "back-order",
    "discontinued": "discontinued", "instoreonly": "in store only",
    "onlineonly": "online only", "onsale": "on sale",
}
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _lean_value(value: Any) -> Any:
    """
    "in stock", not https://schema.org/InStock.

    Consumers relay the canonical term verbatim: a model handed
    https://schema.org/LimitedAvailability answers "LimitedAvailability", which
    is not a sentence in any language. Only values that arrived as a schema.org
    URL are touched, because that prefix is what proves the string is an enum
    rather than ordinary content; without the check a product genuinely named
    "InStock" would be rewritten.
    """
    if not isinstance(value, str) or not value.startswith(_SCHEMA_PREFIX):
        return value
    term = value[len(_SCHEMA_PREFIX):]
    if not term:
        return value
    return _ENUM_WORDS.get(term.lower()) or _CAMEL.sub(" ", term).lower()


def _paths(payload: dict) -> tuple[dict[str, str], set[str]]:
    """(requested-name -> full dotted path, every full path)."""
    where: dict[str, str] = {}
    every: set[str] = set()
    for source in (payload.get("structured_data") or [], payload.get("meta") or {}):
        for path, value in _walk(source):
            if not _keep(value):
                continue
            low = path.lower()
            every.add(low)
            where.setdefault(low, low)
            where.setdefault(low.rsplit(".", 1)[-1], low)
    return where, every


def auto_expand(payload: dict, fields: list[str]) -> list[str]:
    """
    Ask for a leaf, receive the sub-entity holding it.

    A price with no currency is not a cheap answer, it is one you cannot
    transact on. The same defect appears as a street line returned as if it
    were an address, and an opening time with no day attached.

    Rather than a table of per-vertical intents, which is a catalogue nobody
    finishes, this uses the grouping schema.org already did: properties that
    must be read together are properties of the same entity. price lives on an
    Offer, streetAddress on a PostalAddress, ratingValue on an AggregateRating.
    So expand to the containing entity, and no vertical knowledge is needed. A
    clinic's address expands identically to a shop's.

    The root entity is never expanded; that is the full payload with extra
    steps.
    """
    where, every = _paths(payload)
    out: list[str] = []
    for raw in fields:
        name = raw.strip()
        key = name.lower().split("[")[0]
        full = where.get(key) or next(
            (p for k, p in where.items() if k.endswith("." + key)), None)
        if not full or "." not in full:
            out.append(name)          # unknown, or already at an entity's top
            continue
        owner = full.rsplit(".", 1)[0]
        siblings = sorted(
            p for p in every
            if p.startswith(owner + ".") and "." not in p[len(owner) + 1:]
            # @type is plumbing. "offers.@type": "Offer" answers nothing an
            # agent could not read off the field names, and the hours profile
            # already drops it.
            and not p.endswith(".@type"))
        out.extend(siblings or [name])
    seen: set[str] = set()
    return [f for f in out if not (f.lower() in seen or seen.add(f.lower()))]


# Named intents, for the cases that are not structural.
#
# auto_expand covers everything that schema.org groups onto an entity, which is
# most of it. These are the few that are genuinely an intent rather than a
# shape: "contact" spans telephone, email and address, which live on different
# entities, and "hours" needs every openingHoursSpecification entry with its
# position, because "when do you open on Saturday" is unanswerable from an
# index that collapses lists to their first element.
PROFILES: dict[str, tuple[str, ...]] = {
    "price": ("price", "priceCurrency", "availability"),
    "rating": ("ratingValue", "reviewCount", "bestRating"),
    "address": ("streetAddress", "addressLocality", "addressRegion",
                "postalCode", "addressCountry"),
    "contact": ("telephone", "email", "streetAddress", "addressLocality",
                "addressCountry"),
    "hours": ("openingHoursSpecification",),
}


def _positional_paths(payload: dict) -> list[str]:
    """Indexed paths in the casing the publisher used, in document order."""
    out: list[str] = []
    seen: set[str] = set()
    sources = list(payload.get("structured_data") or [])
    sources.append(payload.get("meta") or {})
    for source in sources:
        for path, value in _walk_indexed(source):
            if not _keep(value) or path.lower() in seen:
                continue
            seen.add(path.lower())
            out.append(path)
    return out


def expand_profiles(payload: dict, names: list[str]) -> list[str]:
    """Turn profile names into the field list that answers them completely."""
    out: list[str] = []
    for raw in names:
        key = raw.strip().lower()
        keys = PROFILES.get(key)
        if not keys:
            continue
        if key == "hours":
            # Publisher casing, not the lowercased index key: the response uses
            # the requested name verbatim, and openinghoursspecification[1].opens
            # is not a field name anyone wrote. @type is dropped as plumbing.
            hours = [p for p in _positional_paths(payload)
                     if p.lower().startswith("openinghoursspecification[")
                     and not p.lower().endswith(".@type")]
            out.extend(hours or list(keys))
        else:
            out.extend(keys)
    return out


def resolve(payload: dict, fields: list[str], lean: bool = False) -> dict:
    """
    Return only the requested typed fields, plus the subject they belong to.

    lean drops the per-response envelope: the @context and protocol banner an
    agent learned once from the manifest, the URL it just requested, and the
    schema.org host on enum values. Field names are kept, because they are what
    make an answer checkable and BPE makes them nearly free: English is what
    the tokenizer was fit on.

    Measured live through a gateway, lean is 2.1x smaller than the enveloped
    form and delivers identical facts.
    """
    idx = index_fields(payload)
    out: dict[str, Any] = {} if lean else {
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
    subject = subject_of(payload)
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
                out[name] = _lean_value(positional[key]) if lean else positional[key]
            else:
                unresolved.append(name)
            continue

        if key in idx:
            out[name] = _lean_value(idx[key]) if lean else idx[key]
            continue
        hit = next((v for p, v in idx.items()
                    if p.endswith("." + key) or p == key), None)
        if hit is not None:
            out[name] = _lean_value(hit) if lean else hit
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
    lean = control.get("ubag") == "lean"

    if "ubag.manifest" in control:
        return manifest(payload), "manifest"

    if "ubag.profile" in control:
        names = parse_fields(control["ubag.profile"])
        if [n.strip().lower() for n in names] == ["auto"]:
            # ?ubag.fields=price&ubag.profile=auto
            #
            # Expand each requested leaf to the sub-entity holding it, so a
            # price cannot arrive without its currency. Derived from the
            # publisher's own structure rather than a table of intents, which
            # is why it works on a vertical nobody anticipated.
            asked = parse_fields(control.get("ubag.fields", ""))
            if asked:
                body = resolve(payload, auto_expand(payload, asked), lean=lean)
                return body, "auto-lean" if lean else "auto"

        expanded = expand_profiles(payload, names)
        if expanded:
            fields = expanded + parse_fields(control.get("ubag.fields", ""))
            return resolve(payload, fields, lean=lean), \
                "profile-lean" if lean else "profile"
        # An unrecognised profile name falls through to ubag.fields rather than
        # claiming the mode. Reporting "profile" for a request no profile served
        # would make a typo indistinguishable from a page with no data.

    if "ubag.fields" in control:
        body = resolve(payload, parse_fields(control["ubag.fields"]), lean=lean)
        return body, "lean" if lean else "scoped"

    if control.get("ubag") == "compact":
        from ._compact import compact
        return compact(payload), "compact"
    # Unrecognised values fall through rather than erroring. A caller sending a
    # mode we do not have should still get a usable page.
    return payload, "full"
