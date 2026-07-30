'use strict';

/**
 * UBAG Provenance Profile 1.0 draft.
 *
 * This module ends at VerifiedProvenance. Tenant/principal resolution belongs
 * to the private gateway and must never consume client-authored identity claims.
 */
const crypto = require('crypto');
const { MemoryReplayStore, ReplayStoreCapacityError } = require('./challenge');
const { agentSign, agentVerify } = require('./keys');

const PROFILE_TYPE = 'ubag-provenance+jwt';
const MAX_LIFETIME = 60;
const MAX_CLOCK_SKEW = 5;
const MAX_JTI_BYTES = 128;
const MAX_ENVELOPE_BYTES = 65536;
const MAX_HEADER_BYTES = 4096;
const MAX_PAYLOAD_BYTES = 16384;
const HEADER_FIELDS = new Set(['typ', 'alg', 'jwk', 'kid']);
const PAYLOAD_FIELDS = new Set([
  'jti', 'htm', 'htu', 'iat', 'exp', 'ath', 'ubag_qsh',
  'ubag_content_digest', 'nonce',
]);
const FORBIDDEN_FIELDS = new Set(['tenant', 'tenant_ref', 'principal', 'principal_ref']);
// Replay identifiers are "{originHash}:{agentHash}|{jti}". Both hashes are
// unpadded base64url, so neither can contain ':' or '|', while a client-controlled
// jti may contain both. Taking element [0] is what makes that safe, and it is also
// what keeps the two SDKs identical: JavaScript's split(sep, limit) bounds the
// number of returned elements and Python's split(sep, maxsplit) bounds the number
// of splits, so only [0] agrees under both. Do not replace either extractor with
// lastIndexOf-based parsing or a regex.
const defaultProvenanceStore = new MemoryReplayStore(100000, {
  maxEntriesPerNamespace: 4096,
  namespaceExtractor: (identifier) => identifier.split('|', 1)[0],
  maxEntriesPerGroup: 20000,
  groupExtractor: (identifier) => identifier.split(':', 1)[0],
});

class ProvenanceError extends Error {
  constructor(code, message = '', { agentRef = null } = {}) {
    super(message || code);
    this.code = code;
    this.agentRef = agentRef;
  }
}

const b64u = (value) => Buffer.from(value).toString('base64url');
const decode = (value) => {
  if (typeof value !== 'string' || value.length === 0) throw new Error('invalid base64url');
  return Buffer.from(value, 'base64url');
};

function parseProvenance(compactJws) {
  try {
    if (typeof compactJws !== 'string') throw new Error('string required');
    if (Buffer.byteLength(compactJws, 'utf8') > MAX_ENVELOPE_BYTES) {
      throw new Error('envelope too large');
    }
    const parts = compactJws.split('.');
    if (parts.length !== 3 || parts.some((part) => !part)) throw new Error('three parts required');
    const headerBytes = decode(parts[0]);
    const payloadBytes = decode(parts[1]);
    if (headerBytes.length > MAX_HEADER_BYTES || payloadBytes.length > MAX_PAYLOAD_BYTES) {
      throw new Error('JWS component too large');
    }
    const header = JSON.parse(headerBytes.toString('utf8'));
    const payload = JSON.parse(payloadBytes.toString('utf8'));
    if (!header || Array.isArray(header) || typeof header !== 'object' ||
        !payload || Array.isArray(payload) || typeof payload !== 'object') {
      throw new Error('objects required');
    }
    validateNumberDomain(header);
    validateNumberDomain(payload);
    if (!headerBytes.equals(Buffer.from(JSON.stringify(stable(header)), 'utf8'))) {
      throw new Error('protected header is not RFC 8785 canonical JSON');
    }
    if (!payloadBytes.equals(Buffer.from(JSON.stringify(stable(payload)), 'utf8'))) {
      throw new Error('payload is not RFC 8785 canonical JSON');
    }
    if (Object.keys(header).some((key) => !HEADER_FIELDS.has(key)) || header.crit !== undefined) {
      throw new ProvenanceError('UNSUPPORTED_PROFILE');
    }
    if (Object.keys(payload).some((key) => FORBIDDEN_FIELDS.has(key))) {
      throw new ProvenanceError('INVALID_CLAIMS');
    }
    if (Object.keys(payload).some((key) => !PAYLOAD_FIELDS.has(key))) {
      throw new ProvenanceError('INVALID_CLAIMS');
    }
    return {
      compactJws,
      header,
      payload,
      payloadBytes,
      signingInput: Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'),
      signature: parts[2],
    };
  } catch (error) {
    if (error instanceof ProvenanceError) throw error;
    throw new ProvenanceError('MALFORMED_ENVELOPE');
  }
}

function contentDigest(body = Buffer.alloc(0)) {
  const raw = Buffer.isBuffer(body) ? body : Buffer.from(body);
  return `sha-256=:${crypto.createHash('sha256').update(raw).digest('base64')}:`;
}

function validateNumberDomain(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) {
      throw new ProvenanceError('MALFORMED_ENVELOPE',
        'numbers must be interoperable safe integers');
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach(validateNumberDomain);
    return;
  }
  if (value && typeof value === 'object') {
    Object.values(value).forEach(validateNumberDomain);
    return;
  }
  throw new ProvenanceError('MALFORMED_ENVELOPE');
}

function queryStringHash(originForm) {
  if (typeof originForm !== 'string' || !originForm.startsWith('/') || originForm.includes('#')) {
    throw new Error("originForm must begin with '/' and contain no fragment");
  }
  return crypto.createHash('sha256').update(Buffer.from(originForm, 'utf8')).digest('base64url');
}

function jwkThumbprint(publicKey) {
  const canonical = JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: publicKey });
  return crypto.createHash('sha256').update(canonical).digest('base64url');
}

function agentRef(publicKey) {
  return `ubag:sha256:${crypto.createHash('sha256').update(decode(publicKey)).digest('base64url')}`;
}

function credentialHash(token) {
  return crypto.createHash('sha256').update(String(token), 'utf8').digest('base64url');
}

function checkedPublicKey(header) {
  if (header.typ !== PROFILE_TYPE || header.alg !== 'EdDSA') {
    throw new ProvenanceError('UNSUPPORTED_PROFILE');
  }
  const jwk = header.jwk;
  if (!jwk || Array.isArray(jwk) || typeof jwk !== 'object' ||
      Object.keys(jwk).sort().join(',') !== 'crv,kty,x' ||
      jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') {
    throw new ProvenanceError('UNSUPPORTED_PROFILE');
  }
  if (typeof jwk.x !== 'string' || decode(jwk.x).length !== 32) {
    throw new ProvenanceError('UNSUPPORTED_PROFILE');
  }
  return jwk.x;
}

function verifyProvenance(compactJws, {
  method,
  publicOrigin,
  originForm,
  body = Buffer.alloc(0),
  credential = null,
  credentialValidator = null,
  replayStore = null,
  expectedNonce = null,
  now = null,
}) {
  const envelope = parseProvenance(compactJws);
  const publicKey = checkedPublicKey(envelope.header);
  if (!agentVerify(publicKey, envelope.signingInput, envelope.signature)) {
    throw new ProvenanceError('INVALID_SIGNATURE');
  }
  const derivedAgentRef = agentRef(publicKey);
  if (envelope.header.kid !== undefined && envelope.header.kid !== derivedAgentRef) {
    throw new ProvenanceError('KEY_HINT_MISMATCH');
  }
  const p = envelope.payload;
  const required = ['jti', 'htm', 'htu', 'iat', 'exp', 'ubag_qsh', 'ubag_content_digest'];
  if (required.some((name) => p[name] === undefined) ||
      ['jti', 'htm', 'htu', 'ubag_qsh', 'ubag_content_digest']
        .some((name) => typeof p[name] !== 'string' || p[name].length === 0) ||
      !Number.isInteger(p.iat) || !Number.isInteger(p.exp) ||
      p.exp <= p.iat || p.exp - p.iat > MAX_LIFETIME) {
    throw new ProvenanceError('INVALID_CLAIMS');
  }
  if (Buffer.byteLength(p.jti, 'utf8') > MAX_JTI_BYTES) {
    throw new ProvenanceError('INVALID_CLAIMS', 'jti exceeds 128 bytes');
  }
  const current = now === null ? Math.floor(Date.now() / 1000) : Number(now);
  if (p.iat > current + MAX_CLOCK_SKEW || p.exp < current - MAX_CLOCK_SKEW) {
    throw new ProvenanceError('PROOF_EXPIRED');
  }
  const expectedMethod = String(method).toUpperCase();
  if (p.htm !== expectedMethod) throw new ProvenanceError('METHOD_MISMATCH');
  const path = originForm.split('?', 1)[0];
  const expectedHtu = String(publicOrigin).replace(/\/+$/, '') + path;
  if (p.htu !== expectedHtu) throw new ProvenanceError('ORIGIN_MISMATCH');
  if (p.ubag_qsh !== queryStringHash(originForm)) throw new ProvenanceError('TARGET_MISMATCH');
  const expectedDigest = contentDigest(body);
  if (p.ubag_content_digest !== expectedDigest) {
    throw new ProvenanceError('CONTENT_DIGEST_MISMATCH');
  }

  let claims = null;
  if (credential === null || credential === undefined) {
    if (Object.prototype.hasOwnProperty.call(p, 'ath')) {
      throw new ProvenanceError('CREDENTIAL_MISMATCH');
    }
  } else {
    if (typeof credentialValidator !== 'function') {
      throw new ProvenanceError('VERIFIER_MISCONFIGURED',
        'credential validator is required');
    }
    if (p.ath !== credentialHash(credential)) {
      throw new ProvenanceError('CREDENTIAL_MISMATCH');
    }
    claims = credentialValidator(credential);
    if (!claims || typeof claims !== 'object' || !claims.cnf ||
        claims.cnf.jkt !== jwkThumbprint(publicKey)) {
      throw new ProvenanceError('CREDENTIAL_MISMATCH');
    }
  }

  if (expectedNonce !== null) {
    if (p.nonce !== expectedNonce) throw new ProvenanceError('NONCE_MISMATCH');
  } else if (p.nonce !== undefined) {
    throw new ProvenanceError('NONCE_MISMATCH');
  }

  const store = replayStore || defaultProvenanceStore;
  const originNamespace = crypto.createHash('sha256')
    .update(String(publicOrigin).replace(/\/+$/, ''), 'utf8')
    .digest('base64url');
  const agentNamespace = crypto.createHash('sha256')
    .update(derivedAgentRef, 'utf8')
    .digest('base64url');
  let consumed;
  try {
    consumed = store.consume(`${originNamespace}:${agentNamespace}|${p.jti}`,
      p.exp + MAX_CLOCK_SKEW + 1);
  } catch (error) {
    if (error instanceof ReplayStoreCapacityError) {
      if (error.tier === 'namespace') {
        throw new ProvenanceError('REPLAY_KEY_QUOTA_EXCEEDED', '', {
          agentRef: derivedAgentRef,
        });
      }
      if (error.tier === 'group') {
        throw new ProvenanceError('REPLAY_ORIGIN_QUOTA_EXCEEDED');
      }
      throw new ProvenanceError('REPLAY_STORE_EXHAUSTED');
    }
    throw error;
  }
  if (!consumed) {
    throw new ProvenanceError('PROVENANCE_REPLAYED');
  }
  return Object.freeze({
    agentRef: derivedAgentRef,
    publicKey,
    credentialRef: claims ? claims.jti : null,
    issuer: claims ? claims.iss : null,
    audience: claims ? claims.aud : null,
    method: expectedMethod,
    htu: expectedHtu,
    originForm,
    contentDigest: expectedDigest,
    jti: p.jti,
    issuedAt: p.iat,
    expiresAt: p.exp,
    nonce: p.nonce || null,
  });
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  return value;
}

function createProvenance(privateKey, publicKey, {
  method,
  publicOrigin,
  originForm,
  body = Buffer.alloc(0),
  credential = null,
  jti,
  issuedAt = Math.floor(Date.now() / 1000),
  lifetime = MAX_LIFETIME,
  nonce = null,
  kid = null,
}) {
  if (!Number.isInteger(lifetime) || lifetime < 1 || lifetime > MAX_LIFETIME) {
    throw new Error('lifetime must be between 1 and 60 seconds');
  }
  const path = originForm.split('?', 1)[0];
  const header = {
    typ: PROFILE_TYPE,
    alg: 'EdDSA',
    jwk: { kty: 'OKP', crv: 'Ed25519', x: publicKey },
  };
  if (kid) {
    if (kid !== agentRef(publicKey)) throw new Error('kid must equal the reference derived from publicKey');
    header.kid = kid;
  }
  const payload = {
    jti,
    htm: String(method).toUpperCase(),
    htu: String(publicOrigin).replace(/\/+$/, '') + path,
    iat: Number(issuedAt),
    exp: Number(issuedAt) + lifetime,
    ubag_qsh: queryStringHash(originForm),
    ubag_content_digest: contentDigest(body),
  };
  if (credential !== null && credential !== undefined) payload.ath = credentialHash(credential);
  if (nonce !== null && nonce !== undefined) payload.nonce = nonce;
  const encodedHeader = b64u(Buffer.from(JSON.stringify(stable(header))));
  const encodedPayload = b64u(Buffer.from(JSON.stringify(stable(payload))));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  return `${signingInput}.${agentSign(privateKey, signingInput)}`;
}

module.exports = {
  PROFILE_TYPE,
  ProvenanceError,
  parseProvenance,
  contentDigest,
  queryStringHash,
  jwkThumbprint,
  agentRef,
  credentialHash,
  verifyProvenance,
  createProvenance,
};
