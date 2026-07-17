'use strict';

function buildAgentsJson(host, { credentialEndpoint = '', contact = '' } = {}) {
  // A self-issuing site verifies identity and applies its authorization policy
  // at /ubag/verify when no external credential endpoint is configured.
  credentialEndpoint = credentialEndpoint || `https://${host}/ubag/verify`;
  const doc = {
    ubag_version: '1.0',
    host,
    credential_endpoint: credentialEndpoint,
    branches: {
      'B-AGENT': {
        description: 'Authorized MCP agents — receive clean JSON-LD structured data',
        requires: 'Trusted X-UBAG-Credential JWT plus v2 proof-of-possession',
        content_type: 'application/ld+json',
      },
      'A-HUMAN': {
        description: 'Human browsers — transparently proxied to origin',
        requires: 'None',
      },
      'C-SANDBOX': {
        description: 'Unknown agents — Ed25519 nonce-signature challenge',
        requires: 'Solve challenge to verify identity; site policy controls credential issuance',
        challenge_endpoint: '/ubag/verify',
      },
    },
    discovery: {
      ubag_json:        `https://${host}/.well-known/ubag.json`,
      verify_endpoint:  `https://${host}/ubag/verify`,
      jwks_endpoint:    `https://${host}/.well-known/jwks.json`,
    },
  };
  if (contact) doc.contact = contact;
  return doc;
}

module.exports = { buildAgentsJson };
