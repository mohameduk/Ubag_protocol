"""
HTML → Markdown for the honest-fallback content layer.

Tier 1 serves the structured data a site *declares* (typed, verified). But most
pages have prose the owner never encoded as JSON-LD. Rather than *guess* types
for it (a regex that calls "$19.99" a price is a lie an agent will act on), we
convert the readable page content to Markdown and serve it as clearly-labeled
UNSTRUCTURED text. The agent sees "here is the page's readable content," not
"here are verified facts." That honest labeling is the whole point.

Deterministic, stdlib only. Boilerplate (script/style/nav/header/footer/aside/
form) is stripped first so the agent gets content, not chrome.

Note: unlike the JSON-LD path, Markdown output is NOT promised to be byte-
identical across the Python and Node SDKs — HTML-to-text differs by parser. It
is deterministic within each SDK and semantically equivalent across them.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser

_SKIP_TAGS = {
    "head", "title", "script", "style", "noscript", "template", "svg", "nav",
    "header", "footer", "aside", "form", "button", "iframe",
}
_HEADINGS = {"h1", "h2", "h3", "h4", "h5", "h6"}
_BLOCK = {"p", "div", "section", "article", "main", "table", "tr"}


class _MdConverter(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0
        self._pre = 0
        self._list: list[list] = []  # [tag, counter]
        self._href: str | None = None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in _SKIP_TAGS:
            self._skip += 1
            return
        if self._skip:
            return
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in _HEADINGS:
            self.parts.append("\n\n" + "#" * int(tag[1]) + " ")
        elif tag in _BLOCK:
            self.parts.append("\n\n")
        elif tag == "br":
            self.parts.append("\n")
        elif tag == "hr":
            self.parts.append("\n\n---\n\n")
        elif tag in ("ul", "ol"):
            self._list.append([tag, 0])
            self.parts.append("\n")
        elif tag == "li":
            indent = "  " * max(0, len(self._list) - 1)
            if self._list and self._list[-1][0] == "ol":
                self._list[-1][1] += 1
                self.parts.append(f"\n{indent}{self._list[-1][1]}. ")
            else:
                self.parts.append(f"\n{indent}- ")
        elif tag in ("strong", "b"):
            self.parts.append("**")
        elif tag in ("em", "i"):
            self.parts.append("*")
        elif tag == "code" and not self._pre:
            self.parts.append("`")
        elif tag == "pre":
            self._pre += 1
            self.parts.append("\n\n```\n")
        elif tag == "blockquote":
            self.parts.append("\n\n> ")
        elif tag == "a":
            self._href = a.get("href") or None
            self.parts.append("[")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TAGS:
            self._skip = max(0, self._skip - 1)
            return
        if self._skip:
            return
        if tag in ("strong", "b"):
            self.parts.append("**")
        elif tag in ("em", "i"):
            self.parts.append("*")
        elif tag == "code" and not self._pre:
            self.parts.append("`")
        elif tag == "pre":
            self._pre = max(0, self._pre - 1)
            self.parts.append("\n```\n\n")
        elif tag in ("ul", "ol"):
            if self._list:
                self._list.pop()
            self.parts.append("\n")
        elif tag == "a":
            href, self._href = self._href, None
            self.parts.append(f"]({href})" if href else "]")
        elif tag in _HEADINGS or tag in _BLOCK:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        if self._pre:
            self.parts.append(data)
        else:
            self.parts.append(re.sub(r"\s+", " ", data))


def _strip_boilerplate(html: str) -> str:
    for tag in _SKIP_TAGS:
        html = re.sub(
            rf"<{tag}\b[^>]*>.*?</{tag}>", " ", html, flags=re.IGNORECASE | re.DOTALL
        )
    return html


def _normalize(md: str) -> str:
    md = re.sub(r"[ \t]+\n", "\n", md)     # strip trailing spaces on lines
    md = re.sub(r"\n{3,}", "\n\n", md)     # collapse runs of blank lines
    md = re.sub(r"[ \t]{2,}", " ", md)     # collapse internal runs of spaces
    return md.strip()


def html_to_markdown(html: str, max_chars: int | None = None) -> str:
    """Convert an HTML document to readable Markdown. Boilerplate is removed;
    output is deterministic. Truncated to `max_chars` with a marker if set.
    """
    conv = _MdConverter()
    try:
        conv.feed(_strip_boilerplate(html or ""))
    except Exception:
        pass
    md = _normalize("".join(conv.parts))
    if max_chars and len(md) > max_chars:
        md = md[:max_chars].rstrip() + "\n\n… [truncated]"
    return md
