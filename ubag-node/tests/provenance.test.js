'use strict';

const fs = require('fs');
const path = require('path');
const { MemoryReplayStore } = require('../src/challenge');
const {
  ProvenanceError,
  createProvenance,
  jwkThumbprint,
  verifyProvenance,
} = require('../src/provenance');
const { agentSign } = require('../src/keys');

const vectors = JSON.parse(fs.readFileSync(
  path.join(__dirname, '../../docs/spec/test-vectors/v1.json'), 'utf8'
));
const fixed = vectors.fixed;

function proof(overrides = {}) {
  return createProvenance(fixed.private_key, fixed.public_key, {
    method: fixed.method,
    publicOrigin: fixed.public_origin,
    originForm: fixed.origin_form,
    body: Buffer.from(fixed.body_utf8),
    jti: fixed.jti,
    issuedAt: fixed.issued_at,
    lifetime: fixed.lifetime,
    ...overrides,
  });
}

function verify(value, overrides = {}) {
  return verifyProvenance(value, {
    method: fixed.method,
    publicOrigin: fixed.public_origin,
    originForm: fixed.origin_form,
    body: Buffer.from(fixed.body_utf8),
    now: fixed.issued_at,
    replayStore: new MemoryReplayStore(),
    ...overrides,
  });
}

function code(fn) {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(ProvenanceError);
    return error.code;
  }
  throw new Error('verification unexpectedly succeeded');
}

function signRaw(headerRaw, payloadRaw) {
  const headerPart = Buffer.from(headerRaw).toString('base64url');
  const payloadPart = Buffer.from(payloadRaw).toString('base64url');
  const signingInput = `${headerPart}.${payloadPart}`;
  return `${signingInput}.${agentSign(fixed.private_key, signingInput)}`;
}

test('normative fixed vector is byte-identical and verifies', () => {
  const value = proof();
  expect(value).toBe(fixed.compact_jws);
  expect(verify(value).agentRef).toMatch(/^ubag:sha256:/);
});

test('method, raw target, body, and replay are bound', () => {
  const value = proof();
  expect(code(() => verify(value, { method: 'GET' }))).toBe('METHOD_MISMATCH');
  expect(code(() => verify(value, { originForm: '/payments?a=1&b=2' }))).toBe('TARGET_MISMATCH');
  expect(code(() => verify(value, { body: Buffer.from('{"amount":11}') })))
    .toBe('CONTENT_DIGEST_MISMATCH');
  const store = new MemoryReplayStore();
  verify(value, { replayStore: store });
  expect(code(() => verify(value, { replayStore: store }))).toBe('PROVENANCE_REPLAYED');
});

test('credential presence and key binding are enforced', () => {
  const token = 'signed-credential';
  const value = proof({ credential: token, jti: 'credential-vector' });
  const claims = {
    jti: 'credential-jti',
    iss: 'https://issuer.example',
    aud: 'https://service.example',
    cnf: { jkt: jwkThumbprint(fixed.public_key) },
  };
  expect(verify(value, {
    credential: token,
    credentialValidator: (candidate) => candidate === token ? claims : null,
  }).credentialRef).toBe('credential-jti');
  expect(code(() => verify(value))).toBe('CREDENTIAL_MISMATCH');
});

test('kid can never substitute for the verified key', () => {
  expect(() => proof({ kid: 'ubag:sha256:victim' })).toThrow(
    'kid must equal the reference derived from publicKey'
  );
});

test('default replay store is shared and fails closed', () => {
  const value = proof({ jti: 'node-default-replay-regression' });
  const options = {
    method: fixed.method,
    publicOrigin: fixed.public_origin,
    originForm: fixed.origin_form,
    body: Buffer.from(fixed.body_utf8),
    now: fixed.issued_at,
  };
  verifyProvenance(value, options);
  expect(code(() => verifyProvenance(value, options))).toBe('PROVENANCE_REPLAYED');
});

test('jti, validator configuration, and replay TTL are bounded', () => {
  expect(code(() => verify(proof({ jti: 'x'.repeat(129) })))).toBe('INVALID_CLAIMS');

  const token = 'credential-needing-validator';
  const credentialed = proof({ credential: token, jti: 'missing-validator' });
  expect(code(() => verify(credentialed, { credential: token })))
    .toBe('VERIFIER_MISCONFIGURED');

  const capture = {
    expiresAt: null,
    consume(_identifier, expiresAt) {
      this.expiresAt = expiresAt;
      return true;
    },
  };
  verify(proof({ jti: 'ttl-boundary' }), { replayStore: capture });
  expect(capture.expiresAt).toBe(fixed.issued_at + fixed.lifetime + 6);
});

test('duplicate and non-interoperable numeric JSON fail consistently', () => {
  const [headerPart, payloadPart] = fixed.compact_jws.split('.');
  const header = Buffer.from(headerPart, 'base64url').toString('utf8');
  const payload = Buffer.from(payloadPart, 'base64url').toString('utf8');
  const duplicate = header.replace(
    '{"alg":"EdDSA",', '{"alg":"EdDSA","alg":"EdDSA",'
  );
  expect(code(() => verify(signRaw(duplicate, payload)))).toBe('MALFORMED_ENVELOPE');
  const decimal = payload.replace('"iat":2000000000', '"iat":2000000000.0');
  expect(code(() => verify(signRaw(header, decimal)))).toBe('MALFORMED_ENVELOPE');
  const unsafe = payload.replace('"iat":2000000000', '"iat":9007199254740992');
  expect(code(() => verify(signRaw(header, unsafe)))).toBe('MALFORMED_ENVELOPE');
  const tenantMultifault = `${payload.slice(0, -1)},"tenant":"attacker"}`;
  expect(code(() => verify(signRaw(header, tenantMultifault)))).toBe('MALFORMED_ENVELOPE');
  const headerMultifault = `${header.slice(0, -1)},"aaa":"field"}`;
  expect(code(() => verify(signRaw(headerMultifault, payload)))).toBe('MALFORMED_ENVELOPE');
});

test('replay capacity fails closed without losing prior entry', () => {
  const store = new MemoryReplayStore(1);
  const first = proof({ jti: 'capacity-victim' });
  const second = proof({ jti: 'capacity-flood' });
  verify(first, { replayStore: store });
  expect(code(() => verify(second, { replayStore: store })))
    .toBe('REPLAY_STORE_EXHAUSTED');
  expect(code(() => verify(first, { replayStore: store })))
    .toBe('PROVENANCE_REPLAYED');
});

test('replay namespace quota contains one agent and attributes failure', () => {
  const store = new MemoryReplayStore(10, {
    maxEntriesPerNamespace: 1,
    namespaceExtractor: (identifier) => identifier.split('|', 1)[0],
  });
  verify(proof({ jti: 'agent-quota-first' }), { replayStore: store });
  let failure;
  try {
    verify(proof({ jti: 'agent-quota-second' }), { replayStore: store });
  } catch (error) {
    failure = error;
  }
  expect(failure.code).toBe('REPLAY_KEY_QUOTA_EXCEEDED');
  expect(failure.agentRef).toMatch(/^ubag:sha256:/);

  const otherOrigin = 'https://other.example';
  verify(proof({
    jti: 'other-origin',
    publicOrigin: otherOrigin,
  }), {
    replayStore: store,
    publicOrigin: otherOrigin,
  });
});

test('origin and global exhaustion never blame the rejected agent', () => {
  const originStore = new MemoryReplayStore(10, {
    maxEntriesPerGroup: 1,
    groupExtractor: (identifier) => identifier.split(':', 1)[0],
  });
  verify(proof({ jti: 'origin-first' }), { replayStore: originStore });
  let originFailure;
  try {
    verify(proof({ jti: 'origin-second' }), { replayStore: originStore });
  } catch (error) {
    originFailure = error;
  }
  expect(originFailure.code).toBe('REPLAY_ORIGIN_QUOTA_EXCEEDED');
  expect(originFailure.agentRef).toBeNull();

  const globalStore = new MemoryReplayStore(1);
  verify(proof({ jti: 'global-first' }), { replayStore: globalStore });
  let globalFailure;
  try {
    verify(proof({ jti: 'global-second' }), { replayStore: globalStore });
  } catch (error) {
    globalFailure = error;
  }
  expect(globalFailure.code).toBe('REPLAY_STORE_EXHAUSTED');
  expect(globalFailure.agentRef).toBeNull();
});
