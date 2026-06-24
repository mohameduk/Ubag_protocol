'use strict';

function buildAgentsJson(host, { credentialEndpoint = '', contact = '' } = {}) {
  // A self-issuing site mints credentials at its own /ubag/verify, so when no
  // endpoint is given we advertise that — no hosted central registry required.
  credentialEndpoint = credentialEndpoint || `https://${host}/ubag/verify`;
  const doc = {
    ubag_version: '1.0',
    host,
    credential_endpoint: credentialEndpoint,
    branches: {
      'B-AGENT': {
        description: 'Authorized MCP agents — receive clean JSON-LD structured data',
        requires: 'X-UBAG-Credential header with valid JWT',
        content_type: 'application/ld+json',
      },
      'A-HUMAN': {
        description: 'Human browsers — transparently proxied to origin',
        requires: 'None',
      },
      'C-SANDBOX': {
        description: 'Unknown agents — Ed25519 nonce-signature challenge',
        requires: 'None — solve challenge to get credentialed',
        challenge_endpoint: '/ubag/verify',
      },
    },
    discovery: {
      agents_json:      `https://${host}/agents.json`,
      verify_endpoint:  `https://${host}/ubag/verify`,
      jwks_endpoint:    `https://${host}/.well-known/jwks.json`,
    },
  };
  if (contact) doc.contact = contact;
  return doc;
}

module.exports = { buildAgentsJson };
