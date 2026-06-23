"""
agents.json — machine-readable agent discovery file.

Served automatically at /agents.json on every UBAG-enabled site.
Tells MCP agents how to authenticate and what they can access.
"""
from __future__ import annotations


def build_agents_json(
    host: str,
    credential_endpoint: str = "https://ubagprotocol.com/credential",
    contact: str = "",
    custom_fields: dict | None = None,
) -> dict:
    """
    Build the agents.json discovery document for a given host.

    MCP agents should fetch this before making requests to understand
    what credentials are required and what data is available.
    """
    doc = {
        "ubag_version": "1.0",
        "host": host,
        "credential_endpoint": credential_endpoint,
        "branches": {
            "B-AGENT": {
                "description": "Authorized MCP agents — receive clean JSON-LD structured data",
                "requires": "X-UBAG-Credential header with valid JWT",
                "content_type": "application/ld+json",
            },
            "A-HUMAN": {
                "description": "Human browsers — transparently proxied to origin",
                "requires": "None",
            },
            "C-SANDBOX": {
                "description": "Unknown agents — cryptographic HMAC challenge",
                "requires": "None — solve challenge to get credentialed",
                "challenge_endpoint": "/ubag/verify",
            },
        },
        "discovery": {
            "agents_json": f"https://{host}/agents.json",
            "verify_endpoint": f"https://{host}/ubag/verify",
        },
    }
    if contact:
        doc["contact"] = contact
    if custom_fields:
        doc.update(custom_fields)
    return doc
