"""
FastAPI / Starlette ASGI middleware.

Usage:
    from fastapi import FastAPI
    from ubag import UBAGMiddleware, generate_issuer_keypair

    issuer_private, _ = generate_issuer_keypair()   # EC P-256 (ES256)
    TRUSTED_AGENTS = {"ubag:replace-with-an-approved-agent-id"}

    app = FastAPI()
    app.add_middleware(
        UBAGMiddleware,
        origin="https://yoursite.com",
        issuer_key=issuer_private,                  # mints + verifies credentials
        server_secret="a-separate-strong-secret",
        authorize_agent=lambda identity, request: identity["agent_id"] in TRUSTED_AGENTS,
        site_meta={
            "name": "My Store",
            "type": "Store",
            "description": "We sell widgets",
        },
    )
"""
from __future__ import annotations

import inspect
import json
import os
import threading
import time
from collections import defaultdict, deque
from typing import Any, Callable, Optional

import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ubag._agents_json import build_agents_json
from ubag._challenge import MemoryReplayStore, generate_challenge, verify_challenge, verify_pop
from ubag._cache import TTLCache
from ubag._credential import (
    CREDENTIAL_HEADER,
    DEFAULT_AUDIENCE,
    DEFAULT_ISSUER,
    credential_path_allowed,
    issue_credential,
    validate_credential,
)
from ubag._keys import build_jwks, issuer_public_from_private
from ubag._routing import RoutingBranch, resolve_branch
from ubag._sux import build_jsonld_response


class _SlidingWindowLimiter:
    def __init__(self, limit: int, window: int) -> None:
        self.limit = limit
        self.window = window
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        if self.limit <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            events = self._events[key]
            while events and events[0] <= now - self.window:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(now)
            return True


class UBAGMiddleware(BaseHTTPMiddleware):
    """
    UBAG three-branch routing middleware for FastAPI / Starlette.

    Args:
        app:                  The ASGI application to wrap.
        origin:               The upstream origin URL (Branch A proxy target).
                              e.g. "https://yoursite.com" or "https://192.168.1.1"
        server_secret:        Separate HMAC secret used to stamp nonce challenges.
        site_meta:            Schema.org metadata served to Branch B agents.
                              Keys map directly to JSON-LD fields.
        credential_endpoint:  URL where agents obtain credentials.
        audit_fn:             Optional callback(branch, request, response) for logging.
        on_verified:          Optional callback(claims, request) when a challenge is solved.
    """

    def __init__(
        self,
        app,
        origin: str = "",
        issuer_key: str = "",
        issuer_public_key: str = "",
        server_secret: str = "",
        site_meta: dict[str, Any] | None = None,
        credential_endpoint: str = "",
        audit_fn: Optional[Callable] = None,
        on_verified: Optional[Callable] = None,
        authorize_agent: Optional[Callable] = None,
        allow_self_registration: bool = False,
        is_credential_revoked: Optional[Callable] = None,
        credential_issuer: str = DEFAULT_ISSUER,
        credential_audience: str = DEFAULT_AUDIENCE,
        credential_kid: str = "ubag-issuer-1",
        nonce_store: Any = None,
        pop_store: Any = None,
        verify_rate_limit: int = 30,
        verify_rate_window: int = 60,
        verify_body_max_bytes: int = 16_384,
        verify_tls: bool = True,
        require_pop: bool = True,
        auto_extract: bool = True,
        extract_cache_ttl: int = 300,
        extract_cache_size: int = 256,
        include_markdown: bool = True,
        content_max_chars: int = 20000,
    ) -> None:
        super().__init__(app)
        self.origin              = origin.rstrip("/")
        # Issuer private key (EC P-256 PEM) lets this site MINT credentials; the public
        # key (derived from it) is used to VERIFY. A verify-only site can pass
        # issuer_public_key alone — no secret required to validate, the OAuth/JWKS model.
        self.issuer_private      = issuer_key or os.getenv("UBAG_ISSUER_KEY", "")
        if self.issuer_private:
            self.issuer_public = issuer_public_from_private(self.issuer_private)
        else:
            self.issuer_public = issuer_public_key or os.getenv("UBAG_ISSUER_PUBLIC", "")
        # Separate HMAC key for nonce stamping; never derive it from the issuer key.
        self.server_secret = server_secret or os.getenv("UBAG_SERVER_SECRET", "")
        if not self.server_secret:
            raise ValueError(
                "UBAG: server_secret is required. Set UBAG_SERVER_SECRET or pass "
                "a separate strong server_secret."
            )
        if len(self.server_secret) < 32:
            raise ValueError("UBAG: server_secret must be at least 32 characters.")
        self.site_meta           = site_meta or {}
        self.credential_endpoint = credential_endpoint
        self.audit_fn            = audit_fn
        self.on_verified         = on_verified
        self.authorize_agent     = authorize_agent
        self.allow_self_registration = allow_self_registration
        self.is_credential_revoked = is_credential_revoked
        self.credential_issuer   = credential_issuer
        self.credential_audience = credential_audience
        self.credential_kid      = credential_kid
        self.nonce_store         = nonce_store or MemoryReplayStore()
        self.pop_store           = pop_store or MemoryReplayStore()
        self.verify_body_max_bytes = verify_body_max_bytes
        self._verify_limiter     = _SlidingWindowLimiter(verify_rate_limit, verify_rate_window)
        # SECURITY: verify upstream TLS certs by default. Only disable for
        # explicitly trusted local/dev origins.
        self.verify_tls          = verify_tls
        # SECURITY: require proof-of-possession on credentialed requests so a
        # stolen credential (bearer token) is useless without the agent key.
        self.require_pop         = require_pop
        # Tier 1 auto-extraction: harvest the origin's declared structured data
        # (JSON-LD/OG/meta) for Branch B instead of requiring hand-written
        # site_meta. Only runs when an origin is configured; site_meta always
        # overrides. Fetched HTML is cached (bounded LRU + TTL).
        self.auto_extract        = auto_extract
        self._html_cache         = TTLCache(max_size=extract_cache_size, ttl=extract_cache_ttl)
        # Serve readable page content as clearly-labeled Markdown alongside the
        # declared JSON-LD (honest fallback for pages without full structured
        # data). Marked source=extracted, never mixed into the typed fields.
        self.include_markdown    = include_markdown
        self.content_max_chars   = content_max_chars

        self._http_client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Middleware entry point
    # ------------------------------------------------------------------

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # UBAG system paths — handled here, never forwarded
        if path in ("/.well-known/ubag.json", "/agents.json"):  # /agents.json = legacy alias
            return self._ubag_json_response(request)
        if path == "/.well-known/jwks.json":
            return self._jwks_response()
        if path == "/ubag/verify":
            return await self._handle_verify(request)

        # Routing
        ua         = request.headers.get("user-agent", "")
        accept     = request.headers.get("accept", "")
        cred_token = request.headers.get(CREDENTIAL_HEADER.lower()) or \
                     request.headers.get(CREDENTIAL_HEADER)

        branch = resolve_branch(
            user_agent=ua,
            accept=accept,
            credential_token=cred_token,
            validate_fn=self._validate_token,
        )

        if branch == RoutingBranch.AGENT:
            claims = self._validate_token(cred_token) or {}
            if not credential_path_allowed(claims, request.url.path):
                response = JSONResponse(
                    status_code=403,
                    content={"status": "path_denied", "error": "Credential does not grant this path."},
                    headers={"X-UBAG-Branch": "B-DENIED"},
                )
            elif self.require_pop and not self._pop_ok(request, cred_token, claims):
                # Credential is valid but the caller did not prove possession of
                # the bound agent key → fail closed. Defeats stolen-credential replay.
                response = JSONResponse(
                    status_code=401,
                    content={
                        "status": "pop_required",
                        "error": (
                            "Credential requires UBAG-POP-V2. Send X-UBAG-PoP, "
                            "X-UBAG-PoP-TS, and X-UBAG-PoP-JTI for the exact request target."
                        ),
                    },
                    headers={"X-UBAG-Branch": "B-DENIED"},
                )
            else:
                response = await self._branch_b(request, cred_token)
        elif branch == RoutingBranch.SANDBOX:
            response = self._branch_c(request)
        else:
            if self.origin:
                response = await self._branch_a(request)
            else:
                response = await call_next(request)

        if self.audit_fn:
            try:
                self.audit_fn(branch, request, response)
            except Exception:
                pass

        return response

    def _validate_token(self, token: str) -> dict | None:
        if not token or not self.issuer_public:
            return None
        claims = validate_credential(
            token,
            self.issuer_public,
            issuer=self.credential_issuer,
            audience=self.credential_audience,
        )
        if claims and self.is_credential_revoked:
            try:
                if self.is_credential_revoked(claims):
                    return None
            except Exception:
                return None
        return claims

    # ------------------------------------------------------------------
    # Proof-of-possession gate for credentialed requests
    # ------------------------------------------------------------------

    def _pop_ok(self, request: Request, token: str, claims: dict) -> bool:
        """True if the request carries a valid proof-of-possession for the agent
        key bound to the credential's `cnf` claim. A credential minted without a
        bound key (no `cnf.pub`) cannot satisfy PoP and is rejected when
        require_pop is on — credentials should always be issued with agent_public.
        """
        agent_pub = (claims.get("cnf") or {}).get("pub", "")
        if not agent_pub:
            return False
        target = request.url.path
        if request.url.query:
            target += f"?{request.url.query}"
        host = request.headers.get("host", "").lower()
        return verify_pop(
            agent_public=agent_pub,
            method=request.method,
            host=host,
            target=target,
            token=token,
            ts=request.headers.get("x-ubag-pop-ts", "0"),
            jti=request.headers.get("x-ubag-pop-jti", ""),
            signature=request.headers.get("x-ubag-pop", ""),
            store=self.pop_store,
        )

    # ------------------------------------------------------------------
    # Branch B — Authorized agent → JSON-LD
    # ------------------------------------------------------------------

    async def _branch_b(self, request: Request, token: str) -> JSONResponse:
        claims  = self._validate_token(token)
        host    = request.headers.get("host", "").split(":")[0]
        html    = await self._origin_html(request.url.path)
        payload = build_jsonld_response(
            host=host,
            path=request.url.path,
            site_meta=self.site_meta,
            agent_claims=claims or {},
            html=html,
            include_markdown=self.include_markdown,
            content_max_chars=self.content_max_chars,
        )
        return JSONResponse(
            content=payload,
            media_type="application/ld+json",
            headers={
                "X-UBAG-Branch": "B-AGENT",
                CREDENTIAL_HEADER: token,
            },
        )

    async def _origin_html(self, path: str) -> str | None:
        """Fetch the origin's HTML for `path` so Tier 1 can harvest its declared
        structured data. Cached (bounded LRU + TTL). Returns None — and the
        builder falls back to site_meta only — when extraction is off, no origin
        is configured, the fetch fails, or the response is not HTML.
        """
        if not (self.auto_extract and self.origin):
            return None
        cached = self._html_cache.get(path)
        if cached is not None:
            return cached or None  # "" is a cached negative result
        try:
            client = self._get_http_client()
            url = f"{self.origin}/{path.lstrip('/')}"
            resp = await client.get(url, headers={"accept": "text/html"})
            ctype = resp.headers.get("content-type", "")
            html = resp.text if ("html" in ctype and resp.status_code == 200) else ""
        except Exception:
            html = ""
        self._html_cache.set(path, html)  # cache negatives too, to avoid refetch storms
        return html or None

    # ------------------------------------------------------------------
    # Branch A — Human → transparent proxy to origin
    # ------------------------------------------------------------------

    async def _branch_a(self, request: Request) -> Response:
        client = self._get_http_client()
        full_path = request.url.path
        url = f"{self.origin}/{full_path.lstrip('/')}"
        if request.url.query:
            url += f"?{request.url.query}"

        skip = {"connection", "transfer-encoding", "te", "trailer", "upgrade"}
        headers = {k: v for k, v in request.headers.items() if k.lower() not in skip}
        # Preserve original Host so shared hosting serves the right site
        headers["host"] = request.headers.get("host", "").split(":")[0]
        headers["x-forwarded-for"]   = request.client.host if request.client else "unknown"
        headers["x-forwarded-proto"] = "https"

        body = await request.body()
        resp = await client.request(
            method=request.method,
            url=url,
            headers=headers,
            content=body,
        )

        skip_resp = {"transfer-encoding", "connection", "keep-alive", "upgrade"}
        resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in skip_resp}
        resp_headers["X-UBAG-Branch"] = "A-HUMAN"

        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=resp_headers,
            media_type=resp.headers.get("content-type"),
        )

    # ------------------------------------------------------------------
    # Branch C — Unknown agent → sandbox challenge
    # ------------------------------------------------------------------

    def _branch_c(self, request: Request) -> JSONResponse:
        challenge = generate_challenge(self.server_secret)
        return JSONResponse(
            status_code=429,
            content={
                "status": "challenge_required",
                "ubag_challenge": challenge,
            },
            headers={"X-UBAG-Branch": "C-SANDBOX"},
        )

    # ------------------------------------------------------------------
    # /ubag/verify — agent submits challenge solution
    # ------------------------------------------------------------------

    async def _handle_verify(self, request: Request) -> JSONResponse:
        client_key = request.client.host if request.client else "unknown"
        if not self._verify_limiter.allow(client_key):
            return JSONResponse(status_code=429, content={"error": "rate_limited"})
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self.verify_body_max_bytes:
                    return JSONResponse(status_code=413, content={"error": "request_too_large"})
            except ValueError:
                return JSONResponse(status_code=400, content={"error": "invalid_content_length"})
        try:
            raw_body = await request.body()
            if len(raw_body) > self.verify_body_max_bytes:
                return JSONResponse(status_code=413, content={"error": "request_too_large"})
            body = json.loads(raw_body)
            if not isinstance(body, dict):
                raise ValueError
        except (ValueError, TypeError, json.JSONDecodeError):
            return JSONResponse(status_code=400, content={"error": "invalid_json"})

        try:
            timestamp = int(body.get("timestamp", 0))
        except (TypeError, ValueError):
            return JSONResponse(status_code=400, content={"error": "invalid_timestamp"})

        ok, reason, aid = verify_challenge(
            server_secret=self.server_secret,
            nonce=body.get("nonce", ""),
            timestamp=timestamp,
            stamp=body.get("stamp", ""),
            agent_public=body.get("agent_public", ""),
            signature=body.get("signature", ""),
            store=self.nonce_store,
        )

        if not ok:
            return JSONResponse(status_code=403, content={"status": "failed", "reason": reason})

        if not self.issuer_private:
            # Identity proven, but this site doesn't mint credentials itself —
            # point the agent at the central issuer.
            return JSONResponse(status_code=200, content={
                "status": "identity_verified",
                "agent_id": aid,
                "credential_endpoint": self.credential_endpoint,
                "message": "Identity verified. Obtain a credential from credential_endpoint.",
            })

        authorization: dict[str, Any] | None = None
        if self.authorize_agent:
            result = self.authorize_agent(
                {"agent_id": aid, "agent_public": body.get("agent_public", "")},
                request,
            )
            if inspect.isawaitable(result):
                result = await result
            if result is True:
                authorization = {"agent_class": "authorized_agent", "allowed_paths": ["/*"]}
            elif isinstance(result, dict):
                authorization = result
        elif self.allow_self_registration:
            authorization = {"agent_class": "self_asserted_agent", "allowed_paths": ["/*"]}

        if authorization is None:
            return JSONResponse(status_code=202, content={
                "status": "identity_verified",
                "agent_id": aid,
                "message": "Identity verified; site authorization is required before credential issuance.",
            })

        token = issue_credential(
            subject=aid,
            issuer_private_pem=self.issuer_private,
            agent_public=body.get("agent_public", ""),
            agent_class=authorization.get("agent_class", "authorized_agent"),
            allowed_paths=authorization.get("allowed_paths", ["/*"]),
            issuer=self.credential_issuer,
            audience=self.credential_audience,
            kid=self.credential_kid,
        )

        if self.on_verified:
            try:
                claims = self._validate_token(token)
                self.on_verified(claims, request)
            except Exception:
                pass

        return JSONResponse(
            status_code=200,
            content={
                "status": "credential_issued",
                "credential": token,
                "header": CREDENTIAL_HEADER,
                "instructions": (
                    f"Include '{CREDENTIAL_HEADER}: {token}' plus a v2 request-bound "
                    "proof of possession in future requests."
                ),
            },
        )

    # ------------------------------------------------------------------
    # /.well-known/ubag.json  (alias: /agents.json) — discovery document
    # ------------------------------------------------------------------

    def _ubag_json_response(self, request: Request) -> JSONResponse:
        host = request.headers.get("host", "").split(":")[0]
        doc  = build_agents_json(
            host=host,
            credential_endpoint=self.credential_endpoint,
        )
        return JSONResponse(content=doc, headers={"X-UBAG-Branch": "META"})

    # ------------------------------------------------------------------
    # /.well-known/jwks.json — issuer public key for sites that explicitly
    # trust this issuer (OAuth/JWKS model)
    # ------------------------------------------------------------------

    def _jwks_response(self) -> JSONResponse:
        if not self.issuer_public:
            return JSONResponse(status_code=404, content={"error": "no_issuer_key"})
        return JSONResponse(
            content=build_jwks(self.issuer_public, kid=self.credential_kid),
            headers={"X-UBAG-Branch": "META", "Cache-Control": "public, max-age=3600"},
        )

    # ------------------------------------------------------------------
    # Shared HTTP client for Branch A
    # ------------------------------------------------------------------

    def _get_http_client(self) -> httpx.AsyncClient:
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                follow_redirects=True,
                timeout=30,
                verify=self.verify_tls,
                limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            )
        return self._http_client
