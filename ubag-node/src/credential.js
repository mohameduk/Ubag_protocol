'use strict';

/**
 * Credential issuance/validation (asymmetric, ES256).
 *
 * A credential is a short-lived JWT signed by the ISSUER's EC P-256 private key
 * and verified with the issuer's PUBLIC key (distributable via JWKS). Any site can
 * validate without holding a secret — the OAuth/OIDC model. The credential is
 * bound to the agent's identity key via the `cnf` claim.
 */
const jwt = require('jsonwebtoken');
const { agentId } = require('./keys');

const CREDENTIAL_HEADER = 'X-UBAG-Credential';
const DEFAULT_TTL = 300;
const ALG = 'ES256';

function issueCredential(
  subject,
  issuerPrivatePem,
  {
    agentPublic = null,
    agentClass = 'authorized_agent',
    ttl = DEFAULT_TTL,
    allowedPaths = ['/*'],
    issuer = 'https://ubagprotocol.com',
    kid = 'ubag-issuer-1',
  } = {}
) {
  const payload = { iss: issuer, sub: subject, agent_class: agentClass, paths: allowedPaths };
  if (agentPublic) payload.cnf = { jkt: agentId(agentPublic), pub: agentPublic };
  return jwt.sign(payload, issuerPrivatePem, { algorithm: ALG, expiresIn: ttl, keyid: kid });
}

function validateCredential(token, issuerPublicPem) {
  try {
    return jwt.verify(token, issuerPublicPem, { algorithms: [ALG] });
  } catch {
    return null;
  }
}

module.exports = { CREDENTIAL_HEADER, issueCredential, validateCredential };
