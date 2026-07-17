"""Tier 1 middleware glue — origin fetch, caching, content-type guard."""
import asyncio

import pytest

from ubag import UBAGMiddleware
from ubag._cache import TTLCache
from ubag._keys import generate_issuer_keypair

ISSUER_PRIV, _ = generate_issuer_keypair()

HTML = """<html><head><title>Widget</title>
<meta property="og:type" content="product"></head><body></body></html>"""


# ── TTLCache ──────────────────────────────────────────────────────────────────

def test_ttl_cache_evicts_lru_over_size():
    c = TTLCache(max_size=2, ttl=100)
    c.set("a", 1); c.set("b", 2)
    c.get("a")                 # touch a → b is now LRU
    c.set("c", 3)              # evicts b
    assert c.get("b") is None
    assert c.get("a") == 1 and c.get("c") == 3


def test_ttl_cache_expires():
    c = TTLCache(max_size=8, ttl=-1)   # already expired
    c.set("a", 1)
    assert c.get("a") is None


# ── middleware origin fetch + cache ───────────────────────────────────────────

class _FakeResp:
    def __init__(self, text, status=200, ctype="text/html; charset=utf-8"):
        self.text = text
        self.status_code = status
        self.headers = {"content-type": ctype}


class _FakeClient:
    def __init__(self, resp):
        self._resp = resp
        self.calls = 0

    async def get(self, url, headers=None):
        self.calls += 1
        return self._resp


def _mw(**kw):
    async def app(scope, receive, send):  # minimal ASGI app; unused by these tests
        pass
    return UBAGMiddleware(
        app,
        origin="https://acme.com",
        issuer_key=ISSUER_PRIV,
        server_secret="test-server-secret-separate-from-issuer",
        **kw,
    )


def test_origin_html_fetches_and_caches():
    mw = _mw()
    fake = _FakeClient(_FakeResp(HTML))
    mw._get_http_client = lambda: fake

    html1 = asyncio.run(mw._origin_html("/widget"))
    html2 = asyncio.run(mw._origin_html("/widget"))
    assert "Widget" in html1
    assert html2 == html1
    assert fake.calls == 1          # second call served from cache


def test_non_html_response_is_ignored():
    mw = _mw()
    mw._get_http_client = lambda: _FakeClient(_FakeResp('{"x":1}', ctype="application/json"))
    assert asyncio.run(mw._origin_html("/api/data")) is None


def test_failed_fetch_falls_back_to_none_and_caches_negative():
    mw = _mw()

    class _Boom:
        def __init__(self): self.calls = 0
        async def get(self, url, headers=None):
            self.calls += 1
            raise RuntimeError("origin down")

    boom = _Boom()
    mw._get_http_client = lambda: boom
    assert asyncio.run(mw._origin_html("/x")) is None
    asyncio.run(mw._origin_html("/x"))
    assert boom.calls == 1          # negative result cached, no refetch storm


def test_auto_extract_disabled_skips_fetch():
    mw = _mw(auto_extract=False)
    fake = _FakeClient(_FakeResp(HTML))
    mw._get_http_client = lambda: fake
    assert asyncio.run(mw._origin_html("/widget")) is None
    assert fake.calls == 0
