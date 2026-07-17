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

class MemoryReplayStore {
  constructor(maxEntries = 10000) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1) throw new Error('maxEntries must be positive');
    this.maxEntries = maxEntries;
    this.entries = new Map();
  }

  consume(identifier, expiresAt) {
    const now = Math.floor(Date.now() / 1000);
    for (const [key, expiry] of this.entries) {
      if (expiry <= now) this.entries.delete(key);
    }
    if (this.entries.has(identifier)) return false;
    this.entries.set(identifier, expiresAt);
    while (this.entries.size > this.maxEntries) {
      this.entries.delete(this.entries.keys().next().value);
    }
    return true;
  }
}

const defaultNonceStore = new MemoryReplayStore();
const defaultPopStore = new MemoryReplayStore();

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
  const store = nonceStore || defaultNonceStore;

  if (!nonce || !agent_public || !signature) return [false, 'missing_fields', null];

  const expected = stamp(serverSecret, nonce, timestamp);
  const a = Buffer.from(expected);
  const b = Buffer.from(String(stampIn));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return [false, 'invalid_stamp', null];

  const now = Math.floor(Date.now() / 1000);
  const age = now - timestamp;
  if (age > ttl) return [false, 'nonce_expired', null];
  if (age < -5) return [false, 'nonce_from_future', null];

  // The identity proof: only the holder of the matching private key can produce this.
  if (!agentVerify(agent_public, nonce, signature)) return [false, 'bad_signature', null];

  if (!store.consume(nonce, timestamp + ttl)) return [false, 'nonce_already_used', null];
  return [true, 'identity_verified', agentId(agent_public)];
}

function buildPopMessage(method, host, target, token, ts, jti) {
  const tokenHash = crypto.createHash('sha256').update(String(token)).digest('hex');
  return [
    'UBAG-POP-V2',
    String(method).toUpperCase(),
    String(host).toLowerCase(),
    String(target),
    tokenHash,
    String(ts),
    String(jti),
  ].join('\n');
}

/**
 * V2 proof-of-possession for a credentialed request. The proof binds method,
 * host, path+query, credential thumbprint, timestamp, and a one-time identifier.
 */
function verifyPop(
  agentPublic,
  method,
  host,
  target,
  token,
  ts,
  jti,
  signature,
  { maxAge = 60, replayStore = defaultPopStore } = {}
) {
  if (!agentPublic || !host || !target || !token || !jti || !signature) return false;
  const t = parseInt(ts, 10);
  if (!Number.isFinite(t)) return false;
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - t) > maxAge) return false;
  const message = buildPopMessage(method, host, target, token, t, jti);
  if (!agentVerify(agentPublic, message, signature)) return false;
  return replayStore.consume(`pop:${jti}`, now + maxAge);
}

module.exports = {
  MemoryReplayStore,
  generateChallenge,
  verifyChallenge,
  buildPopMessage,
  verifyPop,
  stamp,
};
