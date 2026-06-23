"""
FastAPI / Starlette ASGI middleware.

Usage:
    from fastapi import FastAPI
    from ubag import UBAGMiddleware

    app = FastAPI()
    app.add_middleware(
        UBAGMiddleware,
        origin="https://yoursite.com",
        secret_key="your-32-char-secret",
        site_meta={
            "name": "My Store",
            "type": "Store",
            "description": "We sell widgets",
        },
    )
"""
from __future__ import annotations

import json
import os
from typing import Any, Callable, Optional

import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ubag._agents_json import build_agents_json
from ubag._challenge import generate_challenge
from ubag._credential import CREDENTIAL_HEADER, validate_credential
from ubag._routing import RoutingBranch, resolve_branch
from ubag._sux import build_jsonld_response


class UBAGMiddleware(BaseHTTPMiddleware):
    """
    UBAG three-branch routing middleware for FastAPI / Starlette.

    Args:
        app:                  The ASGI application to wrap.
        origin:               The upstream origin URL (Branch A proxy target).
                              e.g. "https://yoursite.com" or "https://192.168.1.1"
        secret_key:           HMAC/JWT secret. Must match credentials issued to agents.
                              Defaults to UBAG_SECRET_KEY env var.
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
        secret_key: str = "",
        site_meta: dict[str, Any] | None = None,
        credential_endpoint: str = "https://ubagprotocol.com/credential",
        audit_fn: Optional[Callable] = None,
        on_verified: Optional[Callable] = None,
    ) -> None:
        super().__init__(app)
        self.origin              = origin.rstrip("/")
        self.secret_key          = secret_key or os.getenv("UBAG_SECRET_KEY", "change-me")
        self.site_meta           = site_meta or {}
        self.credential_endpoint = credential_endpoint
        self.audit_fn            = audit_fn
        self.on_verified         = on_verified

        self._http_client: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Middleware entry point
    # ------------------------------------------------------------------

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path

        # UBAG system paths — handled here, never forwarded
        if path == "/agents.json":
            return self._agents_json_response(request)
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
            validate_fn=lambda t: validate_credential(t, self.secret_key),
        )

        if branch == RoutingBranch.AGENT:
            response = self._branch_b(request, cred_token)
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

    # ------------------------------------------------------------------
    # Branch B — Authorized agent → JSON-LD
    # ------------------------------------------------------------------

    def _branch_b(self, request: Request, token: str) -> JSONResponse:
        claims  = validate_credential(token, self.secret_key)
        host    = request.headers.get("host", "").split(":")[0]
        payload = build_jsonld_response(
            host=host,
            path=request.url.path,
            site_meta=self.site_meta,
            agent_claims=claims or {},
        )
        return JSONResponse(
            content=payload,
            media_type="application/ld+json",
            headers={
                "X-UBAG-Branch": "B-AGENT",
                CREDENTIAL_HEADER: token,
            },
        )

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
        client_ip = request.client.host if request.client else "unknown"
        challenge = generate_challenge(self.secret_key, client_ip)
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
        from ubag._challenge import verify_challenge

        try:
            body = await request.json()
        except Exception:
            return JSONResponse(status_code=400, content={"error": "invalid_json"})

        ok, reason = verify_challenge(
            secret_key=self.secret_key,
            nonce_id=body.get("nonce_id", ""),
            timestamp=int(body.get("timestamp", 0)),
            mac=body.get("mac", ""),
            signed_nonce=body.get("signed_nonce", ""),
            delta_ms=float(body.get("delta_ms", 0)),
        )

        if not ok:
            return JSONResponse(status_code=403, content={"status": "failed", "reason": reason})

        subject = body.get("agent_id") or request.client.host or "unknown"
        token   = __import__("ubag._credential", fromlist=["issue_credential"]).issue_credential(
            subject=subject,
            secret_key=self.secret_key,
        )

        if self.on_verified:
            try:
                claims = validate_credential(token, self.secret_key)
                self.on_verified(claims, request)
            except Exception:
                pass

        return JSONResponse(
            status_code=200,
            content={
                "status": "authorized",
                "credential": token,
                "header": CREDENTIAL_HEADER,
                "instructions": f"Include '{CREDENTIAL_HEADER}: {token}' in all future requests.",
            },
        )

    # ------------------------------------------------------------------
    # /agents.json
    # ------------------------------------------------------------------

    def _agents_json_response(self, request: Request) -> JSONResponse:
        host = request.headers.get("host", "").split(":")[0]
        doc  = build_agents_json(
            host=host,
            credential_endpoint=self.credential_endpoint,
        )
        return JSONResponse(content=doc, headers={"X-UBAG-Branch": "META"})

    # ------------------------------------------------------------------
    # Shared HTTP client for Branch A
    # ------------------------------------------------------------------

    def _get_http_client(self) -> httpx.AsyncClient:
        if self._http_client is None or self._http_client.is_closed:
            self._http_client = httpx.AsyncClient(
                follow_redirects=True,
                timeout=30,
                verify=False,
                limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            )
        return self._http_client
