"""
UBAG Protocol — Agent identity and routing middleware.

The missing identity layer for MCP agents.
"""
from ubag._routing import RoutingBranch, resolve_branch
from ubag._credential import issue_credential, validate_credential, CREDENTIAL_HEADER
from ubag._challenge import (
    MemoryReplayStore,
    ReplayStoreCapacityError,
    generate_challenge,
    verify_challenge,
)
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
from ubag.client import Agent, ChallengeFailed, NotIdentified
from ubag.scoped import (
    index_fields,
    manifest,
    parse_fields,
    resolve,
    shape_payload,
    split_ubag_query,
)
from ubag.provenance import (
    ProvenanceEnvelope,
    ProvenanceError,
    VerifiedProvenance,
    create_provenance,
    parse_provenance,
    verify_provenance,
)

# Read from installed metadata rather than restated here.
#
# This said 0.5.0 while pyproject said 0.6.0, through a release. Nothing broke,
# because nothing read it. `ubag init` now does: it stamps the version into the
# skill file it writes and later compares the two to tell the user their copy is
# stale. A hardcoded literal that drifts silently makes that check lie.
#
# The fallback is for running out of a source tree with nothing installed, where
# there is no metadata to read.
try:
    from importlib.metadata import PackageNotFoundError, version as _pkg_version
    try:
        __version__ = _pkg_version("ubag")
    except PackageNotFoundError:
        __version__ = "0.7.0"
except ImportError:  # pragma: no cover
    __version__ = "0.6.0"
__all__ = [
    "Agent",
    "ChallengeFailed",
    "NotIdentified",
    "index_fields",
    "manifest",
    "parse_fields",
    "resolve",
    "shape_payload",
    "split_ubag_query",
    "UBAGMiddleware",
    "AgentCredential",
    "RoutingBranch",
    "resolve_branch",
    "issue_credential",
    "validate_credential",
    "generate_challenge",
    "verify_challenge",
    "MemoryReplayStore",
    "ReplayStoreCapacityError",
    "build_agents_json",
    "CREDENTIAL_HEADER",
    "generate_agent_keypair",
    "generate_issuer_keypair",
    "issuer_public_from_private",
    "agent_id",
    "agent_sign",
    "agent_verify",
    "build_jwks",
    "ProvenanceEnvelope",
    "VerifiedProvenance",
    "ProvenanceError",
    "create_provenance",
    "parse_provenance",
    "verify_provenance",
]

# Lazy import so FastAPI/Starlette is optional
def __getattr__(name: str):
    if name == "UBAGMiddleware":
        from ubag.middleware.fastapi import UBAGMiddleware
        return UBAGMiddleware
    raise AttributeError(f"module 'ubag' has no attribute {name!r}")
