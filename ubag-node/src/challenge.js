'use strict';

/**
 * Branch C — agent identity challenge (asymmetric Ed25519).
 *
 * The agent proves control of its identity key by signing the nonce with its
 * PRIVATE key; the server verifies with the agent's PUBLIC key. The nonce carries
 * a server HMAC `stamp` for stateless issuance (the server signing to itself —
 * not part of the identity proof). The old timing/cadence gate is removed.
 *
 * Replay: provide a shared `nonceStore` in multi-process deployments; the
 * in-memory default only protects a single process.
 */
const crypto = require('crypto');
const { agentVerify, agentId } = require('./keys');

const DEFAULT_TTL = 120;
const _usedNonces = new Set();

function stamp(serverSecret, nonce, ts) {
  return crypto.createHmac('sha256', serverSecret).update(`${nonce}:${ts}`).digest('hex');
}

function generateChallenge(serverSecret, ttl = DEFAULT_TTL) {
  const nonce = crypto.randomBytes(32).toString('base64url');
  const timestamp = Math.floor(Date.now() / 1000);
  return {
    nonce,
    timestamp,
    ttl,
    algo: 'Ed25519',
    stamp: stamp(serverSecret, nonce, timestamp),
    instructions:
      'Sign the `nonce` bytes with your Ed25519 private key and POST ' +
      '{nonce, timestamp, stamp, agent_public, signature} to /ubag/verify.',
  };
}

function verifyChallenge(
  serverSecret,
  { nonce, timestamp, stamp: stampIn, agent_public, signature },
  { ttl = DEFAULT_TTL, nonceStore = null } = {}
) {
  const store =
    nonceStore || { exists: (id) => _usedNonces.has(id), markUsed: (id) => _usedNonces.add(id) };

  if (!nonce || !agent_public || !signature) return [false, 'missing_fields', null];
  if (store.exists(nonce)) return [false, 'nonce_already_used', null];

  const expected = stamp(serverSecret, nonce, timestamp);
  const a = Buffer.from(expected);
  const b = Buffer.from(String(stampIn));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return [false, 'invalid_stamp', null];

  if (Math.floor(Date.now() / 1000) - timestamp > ttl) return [false, 'nonce_expired', null];

  // The identity proof: only the holder of the matching private key can produce this.
  if (!agentVerify(agent_public, nonce, signature)) return [false, 'bad_signature', null];

  store.markUsed(nonce);
  return [true, 'authorized', agentId(agent_public)];
}

module.exports = { generateChallenge, verifyChallenge, stamp };
