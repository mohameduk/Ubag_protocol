"""
ubag.json — machine-readable agent discovery file.

Served automatically at /.well-known/ubag.json on every UBAG-enabled site
(with /agents.json kept as a legacy alias). Tells MCP agents how to authenticate
and what they can access. Deliberately *not* named agents.json — that filename is
already used by unrelated specs (Wildcard, ARD, etc.); ubag.json avoids the clash.
"""
from __future__ import annotations


def build_agents_json(
    host: str,
    credential_endpoint: str = "",
    contact: str = "",
    custom_fields: dict | None = None,
) -> dict:
    """
    Build the ubag.json discovery document for a given host.

    MCP agents should fetch this before making requests to understand
    what credentials are required and what data is available.

    `credential_endpoint` is where an agent proves identity and, when approved
    by site policy, obtains a credential. A self-issuing site handles this at
    `/ubag/verify` when no external endpoint is configured.
    """
    credential_endpoint = credential_endpoint or f"https://{host}/ubag/verify"
    doc = {
        "ubag_version": "1.0",
        "host": host,
        "credential_endpoint": credential_endpoint,
        "branches": {
            "B-AGENT": {
                "description": "Authorized MCP agents — receive clean JSON-LD structured data",
                "requires": "Trusted X-UBAG-Credential JWT plus v2 proof-of-possession",
                "content_type": "application/ld+json",
            },
            "A-HUMAN": {
                "description": "Human browsers — transparently proxied to origin",
                "requires": "None",
            },
            "C-SANDBOX": {
                "description": "Unknown agents — Ed25519 nonce-signature challenge",
                "requires": "Solve challenge to verify identity; site policy controls credential issuance",
                "challenge_endpoint": "/ubag/verify",
            },
        },
        "discovery": {
            "ubag_json": f"https://{host}/.well-known/ubag.json",
            "verify_endpoint": f"https://{host}/ubag/verify",
            "jwks_endpoint": f"https://{host}/.well-known/jwks.json",
        },
    }
    if contact:
        doc["contact"] = contact
    if custom_fields:
        doc.update(custom_fields)
    return doc
