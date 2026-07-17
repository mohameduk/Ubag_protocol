"""
UBAG Protocol — Agent identity and routing middleware.

The missing identity layer for MCP agents.
"""
from ubag._routing import RoutingBranch, resolve_branch
from ubag._credential import issue_credential, validate_credential, CREDENTIAL_HEADER
from ubag._challenge import MemoryReplayStore, generate_challenge, verify_challenge
from ubag._agents_json import build_agents_json
from ubag._keys import (
    generate_agent_keypair,
    generate_issuer_keypair,
    issuer_public_from_private,
    agent_id,
    agent_sign,
    agent_verify,
    build_jwks,
)
from ubag.agent import AgentCredential

__version__ = "0.4.0"
__all__ = [
    "UBAGMiddleware",
    "AgentCredential",
    "RoutingBranch",
    "resolve_branch",
    "issue_credential",
    "validate_credential",
    "generate_challenge",
    "verify_challenge",
    "MemoryReplayStore",
    "build_agents_json",
    "CREDENTIAL_HEADER",
    "generate_agent_keypair",
    "generate_issuer_keypair",
    "issuer_public_from_private",
    "agent_id",
    "agent_sign",
    "agent_verify",
    "build_jwks",
]

# Lazy import so FastAPI/Starlette is optional
def __getattr__(name: str):
    if name == "UBAGMiddleware":
        from ubag.middleware.fastapi import UBAGMiddleware
        return UBAGMiddleware
    raise AttributeError(f"module 'ubag' has no attribute {name!r}")
