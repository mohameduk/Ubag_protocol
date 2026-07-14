"""
AgentCredential — client-side helper for MCP agent developers.

An agent's identity IS its Ed25519 keypair. To get into a UBAG-enabled site the
agent solves the site's nonce challenge by signing it with its private key; the
site (or central issuer) returns a credential the agent then carries.

Usage:
    from ubag import AgentCredential

    agent = AgentCredential.generate(owner="me@example.com")   # once; persist agent.export()
    # ... on a 429 challenge from a site:
    solution = agent.solve_challenge(challenge)                 # POST to /ubag/verify
    agent.set_credential(resp["credential"])                   # store what you get back
    headers = agent.headers()                                   # attach to future requests
"""
from __future__ import annotations

import time
from typing import Optional

from ubag._credential import CREDENTIAL_HEADER
from ubag._keys import agent_id, agent_sign, generate_agent_keypair


class AgentCredential:
    """Holds an agent's identity keypair and (once obtained) its credential token."""

    def __init__(
        self,
        private_key: str,
        public_key: str,
        owner: str = "",
        agent_class: str = "mcp_agent",
    ) -> None:
        self.private_key = private_key
        self.public_key = public_key
        self.owner = owner
        self.agent_class = agent_class
        self.agent_id = agent_id(public_key)
        self._token: Optional[str] = None

    @classmethod
    def generate(cls, owner: str = "", agent_class: str = "mcp_agent") -> "AgentCredential":
        """Create a brand-new agent identity (fresh Ed25519 keypair)."""
        priv, pub = generate_agent_keypair()
        return cls(private_key=priv, public_key=pub, owner=owner, agent_class=agent_class)

    def export(self) -> dict[str, str]:
        """Serialize the identity for persistence. Keep `private_key` secret."""
        return {
            "private_key": self.private_key,
            "public_key": self.public_key,
            "owner": self.owner,
            "agent_class": self.agent_class,
        }

    @classmethod
    def load(cls, data: dict) -> "AgentCredential":
        return cls(
            private_key=data["private_key"],
            public_key=data["public_key"],
            owner=data.get("owner", ""),
            agent_class=data.get("agent_class", "mcp_agent"),
        )

    def solve_challenge(self, challenge: dict) -> dict:
        """Sign a site's nonce challenge. Returns the body to POST to /ubag/verify."""
        nonce = challenge["nonce"]
        return {
            "nonce": nonce,
            "timestamp": challenge["timestamp"],
            "stamp": challenge["stamp"],
            "agent_public": self.public_key,
            "signature": agent_sign(self.private_key, nonce.encode()),
        }

    def set_credential(self, token: str) -> None:
        """Store the credential returned by /ubag/verify."""
        self._token = token

    def headers(self, method: str = "GET", path: str = "/") -> dict[str, str]:
        """Headers to attach to a request once a credential has been obtained.

        Emits the credential PLUS a per-request proof-of-possession: a fresh
        Ed25519 signature over "METHOD PATH TIMESTAMP". The gateway checks this
        against the key bound to the credential's `cnf` claim, so a stolen
        credential is useless without this agent's private key. Because the PoP
        is request-scoped, pass the actual method and path of the call.
        """
        if not self._token:
            raise RuntimeError(
                "No credential yet — solve a site challenge and call set_credential() first."
            )
        ts = int(time.time())
        message = f"{method.upper()} {path} {ts}".encode()
        return {
            CREDENTIAL_HEADER: self._token,
            "X-UBAG-PoP": agent_sign(self.private_key, message),
            "X-UBAG-PoP-TS": str(ts),
        }

    def __repr__(self) -> str:
        return f"AgentCredential(agent_id={self.agent_id!r}, agent_class={self.agent_class!r})"
