"""
AgentCredential — client-side helper for MCP agent developers.

Usage:
    from ubag import AgentCredential

    cred = AgentCredential(subject="my-agent-v1", secret_key="shared-secret")
    headers = cred.headers()   # attach to every request
"""
from __future__ import annotations

from ubag._credential import CREDENTIAL_HEADER, issue_credential, validate_credential


class AgentCredential:
    """
    Represents an agent's UBAG credential.

    The secret_key must match the one configured in the UBAGMiddleware
    on the target website, OR be issued by ubagprotocol.com/credential.
    """

    def __init__(
        self,
        subject: str,
        secret_key: str,
        agent_class: str = "mcp_agent",
        ttl: int = 300,
        allowed_paths: list[str] | None = None,
    ) -> None:
        self.subject       = subject
        self.secret_key    = secret_key
        self.agent_class   = agent_class
        self.ttl           = ttl
        self.allowed_paths = allowed_paths or ["/*"]
        self._token: str | None = None

    def token(self) -> str:
        """Return a valid token, re-issuing if expired."""
        if self._token:
            claims = validate_credential(self._token, self.secret_key)
            if claims:
                return self._token
        self._token = issue_credential(
            subject=self.subject,
            secret_key=self.secret_key,
            agent_class=self.agent_class,
            ttl=self.ttl,
            allowed_paths=self.allowed_paths,
        )
        return self._token

    def headers(self) -> dict[str, str]:
        """Return headers dict to attach to every HTTP request."""
        return {CREDENTIAL_HEADER: self.token()}

    def __repr__(self) -> str:
        return f"AgentCredential(subject={self.subject!r}, agent_class={self.agent_class!r})"
