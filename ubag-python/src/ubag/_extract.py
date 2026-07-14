"""
Tier 1 structured-data extraction — harvest what the site already declares.

Most sites already publish structured data for search engines: JSON-LD in
`<script type="application/ld+json">`, OpenGraph `<meta property="og:*">`, and
standard `<meta>`/`<title>`/`<link rel=canonical>` tags. All of it is the site
owner's own declared description of the page. Tier 1 re-serves that to an
authorized agent — nothing here is inferred or guessed, so everything it emits
is trustworthy by construction.

Pure function: HTML string in, a plain dict out. No network, no side effects,
stdlib only (`html.parser`), so it is trivially testable and cannot hallucinate
structure that isn't literally present in the page.
"""
from __future__ import annotations

import json
from html.parser import HTMLParser
from typing import Any, Iterator


class _Harvester(HTMLParser):
    """Single-pass collector for declared structured data."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.jsonld_raw: list[str] = []
        self.metas: list[dict[str, str]] = []
        self.title_parts: list[str] = []
        self.canonical: str | None = None
        self.lang: str | None = None
        self._in_ldjson = False
        self._ld_buf: list[str] = []
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "html" and a.get("lang") and not self.lang:
            self.lang = a["lang"].strip()
        elif tag == "script" and a.get("type", "").strip().lower() == "application/ld+json":
            self._in_ldjson = True
            self._ld_buf = []
        elif tag == "meta":
            self.metas.append(a)
        elif tag == "title":
            self._in_title = True
        elif tag == "link":
            rel = a.get("rel", "").lower()
            if "canonical" in rel and a.get("href") and not self.canonical:
                self.canonical = a["href"].strip()

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._in_ldjson:
            self._in_ldjson = False
            self.jsonld_raw.append("".join(self._ld_buf))
            self._ld_buf = []
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_ldjson:
            self._ld_buf.append(data)
        elif self._in_title:
            self.title_parts.append(data)


def _iter_jsonld(obj: Any) -> Iterator[dict]:
    """Flatten a parsed JSON-LD value into individual node dicts.

    Handles a bare object, a top-level array, and the common `@graph` wrapper.
    """
    if isinstance(obj, list):
        for item in obj:
            yield from _iter_jsonld(item)
    elif isinstance(obj, dict):
        graph = obj.get("@graph")
        if isinstance(graph, list):
            for item in graph:
                yield from _iter_jsonld(item)
        else:
            yield obj


def extract_structured_data(html: str) -> dict[str, Any]:
    """Harvest declared structured data from an HTML string.

    Returns a dict with the raw declared JSON-LD nodes plus normalized OG / meta
    values. Every field is something the owner authored — nothing is inferred.
    Malformed JSON-LD blocks are skipped rather than raising.
    """
    h = _Harvester()
    try:
        h.feed(html)
    except Exception:
        # A broken document still yields whatever was parsed before the error.
        pass

    jsonld: list[dict] = []
    for raw in h.jsonld_raw:
        raw = raw.strip()
        if not raw:
            continue
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            continue
        for node in _iter_jsonld(parsed):
            if isinstance(node, dict):
                jsonld.append(node)

    og: dict[str, str] = {}
    twitter: dict[str, str] = {}
    meta: dict[str, str] = {}
    for m in h.metas:
        content = m.get("content")
        if content is None:
            continue
        prop = m.get("property", "").strip().lower()
        name = m.get("name", "").strip().lower()
        if prop.startswith("og:"):
            og.setdefault(prop[3:], content)
        elif name.startswith("twitter:"):
            twitter.setdefault(name[8:], content)
        elif name in ("description", "keywords", "author"):
            meta.setdefault(name, content)

    title = "".join(h.title_parts).strip() or og.get("title")

    return {
        "jsonld": jsonld,
        "og": og,
        "twitter": twitter,
        "meta": meta,
        "title": title,
        "canonical": h.canonical,
        "lang": h.lang,
    }


# OpenGraph `og:type` values map loosely onto schema.org @type; only a few are
# unambiguous. Everything else stays a generic WebPage rather than being guessed.
_OG_TYPE_TO_SCHEMA = {
    "website": "WebSite",
    "article": "Article",
    "product": "Product",
    "profile": "ProfilePage",
    "book": "Book",
    "video.movie": "Movie",
}


def og_type_to_schema(og_type: str | None) -> str | None:
    if not og_type:
        return None
    return _OG_TYPE_TO_SCHEMA.get(og_type.strip().lower())
