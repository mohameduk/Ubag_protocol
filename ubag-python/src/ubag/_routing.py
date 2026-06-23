"""
Three-branch routing matrix.

Branch A — Human     → transparent proxy to origin
Branch B — Agent     → clean JSON-LD structured data
Branch C — Sandbox   → cryptographic challenge
"""
from __future__ import annotations

import re
from enum import Enum
from typing import Optional


class RoutingBranch(str, Enum):
    HUMAN   = "A-HUMAN"
    AGENT   = "B-AGENT"
    SANDBOX = "C-SANDBOX"


# HTTP library user-agent signatures — these are never human
_MACHINE_UA = re.compile(
    r"(python-httpx|python-requests|aiohttp|curl|wget|go-http-client|"
    r"java\/|okhttp|axios|node-fetch|got\/|undici|libwww|mechanize|"
    r"scrapy|selenium|playwright|puppeteer|headlesschrome|"
    r"GPTBot|ClaudeBot|PerplexityBot|anthropic-ai|Googlebot|bingbot|"
    r"DuckDuckBot|Baiduspider|YandexBot|facebookexternalhit|Twitterbot)",
    re.IGNORECASE,
)

_BROWSER_ACCEPT = re.compile(r"text/html", re.IGNORECASE)
_BROWSER_UA     = re.compile(r"Mozilla|Chrome|Safari|Firefox|Edge", re.IGNORECASE)


def _is_machine(user_agent: str, accept: str) -> bool:
    """
    Heuristic: declared machine UA or missing browser Accept header.
    Errs toward HUMAN for ambiguous traffic (fail open).
    """
    if _MACHINE_UA.search(user_agent):
        return True
    # UA claims to be a browser but sends no text/html Accept — likely a lib
    if _BROWSER_UA.search(user_agent) and not _BROWSER_ACCEPT.search(accept):
        return True
    return False


def resolve_branch(
    user_agent: str,
    accept: str,
    credential_token: Optional[str],
    validate_fn,
) -> RoutingBranch:
    """
    Resolve which branch handles this request.

    Args:
        user_agent:       Value of User-Agent header
        accept:           Value of Accept header
        credential_token: Value of X-UBAG-Credential header (may be None)
        validate_fn:      Callable[str] -> Optional[dict] — verifies the token
    """
    if credential_token:
        claims = validate_fn(credential_token)
        if claims:
            return RoutingBranch.AGENT

    if _is_machine(user_agent, accept):
        return RoutingBranch.SANDBOX

    return RoutingBranch.HUMAN
