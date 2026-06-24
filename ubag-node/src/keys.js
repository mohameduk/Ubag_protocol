'use strict';

/**
 * Asymmetric key primitives for UBAG (mirrors ubag-python/src/ubag/_keys.py).
 *
 *  - Agent identity  -> Ed25519, serialized as RAW base64url keys so a signature
 *    produced here verifies byte-for-byte in the Python SDK and vice-versa.
 *  - Issuer (credential signing) -> EC P-256 / ES256 JWT (PEM), the one asymmetric
 *    JWT algorithm both `jsonwebtoken` and PyJWT support, so credentials are
 *    cross-SDK verifiable via the issuer PUBLIC key (JWKS) — the OAuth/OIDC model.
 */
const crypto = require('crypto');

// Fixed DER wrappers so we can round-trip RAW Ed25519 keys through Node's KeyObject API.
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex'); // 12 bytes
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex'); // 16 bytes

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const unb64u = (s) => Buffer.from(s, 'base64url');

// ── Agent identity (Ed25519, raw b64url) ──────────────────────────────────────
function generateAgentKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubDer = publicKey.export({ format: 'der', type: 'spki' });
  const privDer = privateKey.export({ format: 'der', type: 'pkcs8' });
  return { privateKey: b64u(privDer.subarray(-32)), publicKey: b64u(pubDer.subarray(-32)) };
}

function _privKeyObj(privB64) {
  return crypto.createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, unb64u(privB64)]),
    format: 'der',
    type: 'pkcs8',
  });
}
function _pubKeyObj(pubB64) {
  return crypto.createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, unb64u(pubB64)]),
    format: 'der',
    type: 'spki',
  });
}

function agentSign(privB64, message) {
  return b64u(crypto.sign(null, Buffer.from(message), _privKeyObj(privB64)));
}
function agentVerify(pubB64, message, signatureB64) {
  try {
    return crypto.verify(null, Buffer.from(message), _pubKeyObj(pubB64), unb64u(signatureB64));
  } catch {
    return false;
  }
}
function agentId(pubB64) {
  const digest = crypto.createHash('sha256').update(unb64u(pubB64)).digest('base64url');
  return 'ubag:' + digest.slice(0, 43);
}

// ── Issuer keys (EC P-256, for ES256 credential JWTs) ─────────────────────────
function generateIssuerKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { privateKey, publicKey };
}
function issuerPublicFromPrivate(privPem) {
  return crypto.createPublicKey(privPem).export({ type: 'spki', format: 'pem' });
}
function buildJwks(pubPem, kid = 'ubag-issuer-1') {
  const jwk = crypto.createPublicKey(pubPem).export({ format: 'jwk' });
  return { keys: [{ ...jwk, use: 'sig', alg: 'ES256', kid }] };
}

module.exports = {
  b64u,
  unb64u,
  generateAgentKeypair,
  agentSign,
  agentVerify,
  agentId,
  generateIssuerKeypair,
  issuerPublicFromPrivate,
  buildJwks,
};
