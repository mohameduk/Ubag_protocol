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

class ReplayStoreCapacityError extends Error {
  constructor(message = 'replay store is full of live entries; refusing to fail open',
    { tier = 'global', namespace = null } = {}) {
    super(message);
    this.name = 'ReplayStoreCapacityError';
    this.tier = tier;
    this.namespace = namespace;
  }
}

class MemoryReplayStore {
  constructor(maxEntries = 10000, {
    maxEntriesPerNamespace = null,
    namespaceExtractor = null,
    maxEntriesPerGroup = null,
    groupExtractor = null,
  } = {}) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1) throw new Error('maxEntries must be positive');
    this.maxEntries = maxEntries;
    if (maxEntriesPerNamespace !== null &&
        (!Number.isInteger(maxEntriesPerNamespace) || maxEntriesPerNamespace < 1)) {
      throw new Error('maxEntriesPerNamespace must be positive');
    }
    this.maxEntriesPerNamespace = maxEntriesPerNamespace;
    this.namespaceExtractor = namespaceExtractor;
    if (maxEntriesPerGroup !== null &&
        (!Number.isInteger(maxEntriesPerGroup) || maxEntriesPerGroup < 1)) {
      throw new Error('maxEntriesPerGroup must be positive');
    }
    this.maxEntriesPerGroup = maxEntriesPerGroup;
    this.groupExtractor = groupExtractor;
    this.entries = new Map();
    this.namespaceCounts = new Map();
    this.groupCounts = new Map();
    this.expiryHeap = [];
    this.capacityExhaustions = 0;
  }

  _less(a, b) {
    return a[0] < b[0] || (a[0] === b[0] && a[1] < b[1]);
  }

  _push(node) {
    const heap = this.expiryHeap;
    heap.push(node);
    let index = heap.length - 1;
    while (index > 0) {
      const parent = Math.floor((index - 1) / 2);
      if (!this._less(heap[index], heap[parent])) break;
      [heap[index], heap[parent]] = [heap[parent], heap[index]];
      index = parent;
    }
  }

  _pop() {
    const heap = this.expiryHeap;
    const first = heap[0];
    const last = heap.pop();
    if (heap.length && last) {
      heap[0] = last;
      let index = 0;
      while (true) {
        const left = index * 2 + 1;
        const right = left + 1;
        let smallest = index;
        if (left < heap.length && this._less(heap[left], heap[smallest])) smallest = left;
        if (right < heap.length && this._less(heap[right], heap[smallest])) smallest = right;
        if (smallest === index) break;
        [heap[index], heap[smallest]] = [heap[smallest], heap[index]];
        index = smallest;
      }
    }
    return first;
  }

  consume(identifier, expiresAt) {
    const now = Math.floor(Date.now() / 1000);
    while (this.expiryHeap.length && this.expiryHeap[0][0] <= now) {
      const [expiry, key] = this._pop();
      if (this.entries.get(key) === expiry) {
        this.entries.delete(key);
        const namespace = this._namespace(key);
        if (namespace !== null) {
          const remaining = Math.max((this.namespaceCounts.get(namespace) || 0) - 1, 0);
          if (remaining) this.namespaceCounts.set(namespace, remaining);
          else this.namespaceCounts.delete(namespace);
        }
        const group = this._group(key);
        if (group !== null) {
          const remaining = Math.max((this.groupCounts.get(group) || 0) - 1, 0);
          if (remaining) this.groupCounts.set(group, remaining);
          else this.groupCounts.delete(group);
        }
      }
    }
    if (this.entries.has(identifier)) return false;
    const namespace = this._namespace(identifier);
    if (namespace !== null && this.maxEntriesPerNamespace !== null &&
        (this.namespaceCounts.get(namespace) || 0) >= this.maxEntriesPerNamespace) {
      this.capacityExhaustions += 1;
      throw new ReplayStoreCapacityError(
        'replay namespace is full of live entries; refusing to fail open',
        { tier: 'namespace', namespace }
      );
    }
    const group = this._group(identifier);
    if (group !== null && this.maxEntriesPerGroup !== null &&
        (this.groupCounts.get(group) || 0) >= this.maxEntriesPerGroup) {
      this.capacityExhaustions += 1;
      throw new ReplayStoreCapacityError(
        'replay group is full of live entries; refusing to fail open',
        { tier: 'group' }
      );
    }
    if (this.entries.size >= this.maxEntries) {
      this.capacityExhaustions += 1;
      throw new ReplayStoreCapacityError(undefined, { tier: 'global' });
    }
    this.entries.set(identifier, expiresAt);
    if (namespace !== null) {
      this.namespaceCounts.set(namespace, (this.namespaceCounts.get(namespace) || 0) + 1);
    }
    if (group !== null) {
      this.groupCounts.set(group, (this.groupCounts.get(group) || 0) + 1);
    }
    this._push([expiresAt, identifier]);
    if (this.expiryHeap.length > 2 * this.entries.size + 64) {
      this.expiryHeap = [];
      for (const [key, expiry] of this.entries) this._push([expiry, key]);
    }
    return true;
  }

  _namespace(identifier) {
    if (typeof this.namespaceExtractor !== 'function') return null;
    return this.namespaceExtractor(identifier);
  }

  _group(identifier) {
    if (typeof this.groupExtractor !== 'function') return null;
    return this.groupExtractor(identifier);
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

  try {
    if (!store.consume(nonce, timestamp + ttl)) return [false, 'nonce_already_used', null];
  } catch (error) {
    if (error instanceof ReplayStoreCapacityError) {
      return [false, 'replay_store_exhausted', null];
    }
    throw error;
  }
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
  try {
    return replayStore.consume(`pop:${jti}`, now + maxAge);
  } catch (error) {
    if (error instanceof ReplayStoreCapacityError) return false;
    throw error;
  }
}

module.exports = {
  ReplayStoreCapacityError,
  MemoryReplayStore,
  generateChallenge,
  verifyChallenge,
  buildPopMessage,
  verifyPop,
  stamp,
};
