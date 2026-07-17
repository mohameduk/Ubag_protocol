'use strict';

/**
 * Credential issuance/validation (asymmetric, ES256).
 *
 * A credential is a short-lived JWT signed by the ISSUER's EC P-256 private key
 * and verified by sites configured to trust the issuer's PUBLIC key, issuer, and
 * audience. The credential is bound to the agent's identity key via `cnf`.
 */
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { agentId } = require('./keys');

const CREDENTIAL_HEADER = 'X-UBAG-Credential';
const DEFAULT_TTL = 300;
const ALG = 'ES256';
const DEFAULT_ISSUER = 'https://ubagprotocol.com';
const DEFAULT_AUDIENCE = 'ubag-web';

function issueCredential(
  subject,
  issuerPrivatePem,
  {
    agentPublic = null,
    agentClass = 'self_asserted_agent',
    ttl = DEFAULT_TTL,
    allowedPaths = ['/*'],
    issuer = DEFAULT_ISSUER,
    audience = DEFAULT_AUDIENCE,
    kid = 'ubag-issuer-1',
  } = {}
) {
  const payload = {
    iss: issuer,
    aud: audience,
    sub: subject,
    jti: crypto.randomUUID(),
    agent_class: agentClass,
    paths: allowedPaths,
  };
  if (agentPublic) payload.cnf = { jkt: agentId(agentPublic), pub: agentPublic };
  return jwt.sign(payload, issuerPrivatePem, { algorithm: ALG, expiresIn: ttl, keyid: kid });
}

function validateCredential(
  token,
  issuerPublicPem,
  { issuer = DEFAULT_ISSUER, audience = DEFAULT_AUDIENCE } = {}
) {
  try {
    const claims = jwt.verify(token, issuerPublicPem, { algorithms: [ALG], issuer, audience });
    if (!claims.sub || !claims.iat || !claims.exp || !claims.jti) return null;
    return claims;
  } catch {
    return null;
  }
}

function credentialPathAllowed(claims, path) {
  const grants = claims && claims.paths;
  if (!Array.isArray(grants) || grants.length === 0) return false;
  return grants.some((pattern) => {
    if (typeof pattern !== 'string') return false;
    const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
    return new RegExp(`^${escaped}$`).test(path);
  });
}

module.exports = {
  CREDENTIAL_HEADER,
  DEFAULT_ISSUER,
  DEFAULT_AUDIENCE,
  issueCredential,
  validateCredential,
  credentialPathAllowed,
};
