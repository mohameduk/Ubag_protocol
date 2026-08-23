"""
One-call scoped retrieval, built on the primitives AgentCredential already has.

AgentCredential handles identity: generate a keypair, solve a challenge, hold a
credential, and produce the proof-of-possession headers for a request. What it
does not do is the HTTP round trip, and the round trip is where adoption dies.
Doing it by hand means: request the page, recognise the 429, pull the challenge
out of the body, solve it, POST to /ubag/verify, find the credential header,
store it, build the query string, attach headers, notice when the credential
expires, and do it again. Forty lines to save tokens the caller has not yet
noticed they are spending.

    from ubag import Agent

    agent = Agent.generate()
    answer = agent.fields("https://shop.example.com/p/3391",
                          ["offers.price", "offers.availability"])

Measured on 63 ground-truth questions through a live gateway: 12.5x fewer input
tokens on gpt-4o-mini, 12.1x on gemini-2.5-flash, accuracy unchanged.

Requires httpx, which the rest of this package does not, so the import stays
local to the methods that need it.
"""
from __future__ import annotations

import time
from typing import Any, Optional
from urllib.parse import quote, urlsplit

from ubag._credential import CREDENTIAL_HEADER
from ubag.agent import AgentCredential

__all__ = ["Agent", "ChallengeFailed", "NotIdentified"]

LEGACY_CREDENTIAL_HEADER = "X-Web-UBAG-Credential"

# Re-identify on this clock rather than waiting to be refused. An expired
# credential drops the caller onto the unauthorized branch, where the reply is
# a challenge that looks like an answer: readable JSON, no error, no fields.
REIDENTIFY_AFTER_SECONDS = 900


class ChallengeFailed(RuntimeError):
    """The site did not issue a credential."""


class NotIdentified(RuntimeError):
    """The site answered as though no credential had been presented."""


class Agent:
    """An identified agent that can ask pages for fields."""

    def __init__(self, credential: AgentCredential, *, timeout: float = 30.0):
        self.credential = credential
        self._timeout = timeout
        self._identified_at = 0.0
        self._origin = ""

    @classmethod
    def generate(cls, owner: str = "", agent_class: str = "mcp_agent",
                 **kw) -> "Agent":
        """A fresh Ed25519 identity. The private key never leaves this process."""
        return cls(AgentCredential.generate(owner=owner,
                                            agent_class=agent_class), **kw)

    @classmethod
    def load(cls, data: dict, **kw) -> "Agent":
        """Reuse a previously exported identity, so the agent ref is stable."""
        return cls(AgentCredential.load(data), **kw)

    @property
    def agent_id(self) -> str:
        return self.credential.agent_id

    def export(self) -> dict:
        return self.credential.export()

    # ------------------------------------------------------------------

    def _http(self):
        import httpx
        return httpx.Client(timeout=self._timeout, follow_redirects=True)

    def identify(self, url: str, client=None) -> None:
        """
        Complete the challenge-response for this site.

        Called automatically. Worth calling directly to fail early against a
        site that does not speak UBAG.
        """
        owns = client is None
        client = client or self._http()
        try:
            parts = urlsplit(url)
            origin = f"{parts.scheme}://{parts.netloc}"

            probe = client.get(url, headers={"Accept": "application/json"})
            if probe.status_code != 429:
                raise ChallengeFailed(
                    f"expected a challenge, got {probe.status_code} on branch "
                    f"{probe.headers.get('X-UBAG-Branch', 'unknown')}")

            body = probe.json().get("ubag_challenge") or probe.json()
            verified = client.post(
                f"{origin}/ubag/verify",
                headers={"Accept": "application/json"},
                json=self.credential.solve_challenge(body),
            )
            if verified.status_code != 200:
                raise ChallengeFailed(
                    f"verify returned {verified.status_code}: "
                    f"{verified.text[:200]}")

            token = (verified.headers.get(CREDENTIAL_HEADER)
                     or verified.headers.get(LEGACY_CREDENTIAL_HEADER))
            if not token:
                raise ChallengeFailed(
                    "verify succeeded but returned no credential header")

            self.credential.set_credential(token)
            self._identified_at = time.time()
            self._origin = origin
        finally:
            if owns:
                client.close()

    def _get(self, url: str, params: str) -> dict[str, Any]:
        with self._http() as client:
            stale = time.time() - self._identified_at > REIDENTIFY_AFTER_SECONDS
            if stale or urlsplit(url).netloc not in self._origin:
                self.identify(url, client=client)

            parts = urlsplit(url)
            target = parts.path or "/"
            if params:
                target = f"{target}?{params}"
            full = f"{self._origin}{target}"

            response = client.get(
                full,
                headers={"Accept": "application/json",
                         **self.credential.headers("GET", full)},
            )

            branch = response.headers.get("X-UBAG-Branch", "unknown")
            if branch != "B-AGENT":
                raise NotIdentified(
                    f"reached branch {branch} with status "
                    f"{response.status_code}")
            if response.status_code >= 400:
                # An error is not a statement about the resource's contents,
                # and must never be returned as though it were one.
                raise NotIdentified(
                    f"{response.status_code}: {response.text[:200]}")
            return response.json()

    # ------------------------------------------------------------------

    def fields(self, url: str, fields: list[str]) -> dict[str, Any]:
        """
        Ask a page for specific typed fields.

        Anything the page cannot answer comes back under ubag:unresolved rather
        than being silently omitted, so absence stays distinguishable from a
        negative answer.
        """
        return self._get(url, f"ubag.fields={quote(','.join(fields), safe=',.[]')}")

    def manifest(self, url: str) -> dict[str, Any]:
        """What this page can answer, without answering. Cacheable per URL."""
        return self._get(url, "ubag.manifest=1")

    def full(self, url: str) -> dict[str, Any]:
        """The whole payload, for when the answer really is the whole page."""
        return self._get(url, "")
