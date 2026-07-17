'use strict';

const { generateChallenge, verifyChallenge, stamp } = require('../src/challenge');
const { generateAgentKeypair, agentSign, agentId } = require('../src/keys');

const SERVER_SECRET = 'server-stamp-secret';
const makeStore = () => {
  const used = new Set();
  return { consume: (id) => used.has(id) ? false : (used.add(id), true) };
};
const solve = (ch, priv) => agentSign(priv, ch.nonce);

test('valid challenge accepted', () => {
  const store = makeStore();
  const { privateKey, publicKey } = generateAgentKeypair();
  const ch = generateChallenge(SERVER_SECRET);
  const [ok, reason, aid] = verifyChallenge(SERVER_SECRET, {
    nonce: ch.nonce, timestamp: ch.timestamp, stamp: ch.stamp,
    agent_public: publicKey, signature: solve(ch, privateKey),
  }, { nonceStore: store });
  expect(ok).toBe(true);
  expect(reason).toBe('identity_verified');
  expect(aid).toBe(agentId(publicKey));
});

test('replay rejected', () => {
  const store = makeStore();
  const { privateKey, publicKey } = generateAgentKeypair();
  const ch = generateChallenge(SERVER_SECRET);
  const args = { nonce: ch.nonce, timestamp: ch.timestamp, stamp: ch.stamp, agent_public: publicKey, signature: solve(ch, privateKey) };
  verifyChallenge(SERVER_SECRET, args, { nonceStore: store });
  const [ok, reason] = verifyChallenge(SERVER_SECRET, args, { nonceStore: store });
  expect(ok).toBe(false);
  expect(reason).toBe('nonce_already_used');
});

test('wrong key rejected', () => {
  const store = makeStore();
  const { publicKey } = generateAgentKeypair();
  const other = generateAgentKeypair();
  const ch = generateChallenge(SERVER_SECRET);
  const [ok, reason] = verifyChallenge(SERVER_SECRET, {
    nonce: ch.nonce, timestamp: ch.timestamp, stamp: ch.stamp,
    agent_public: publicKey, signature: agentSign(other.privateKey, ch.nonce),
  }, { nonceStore: store });
  expect(ok).toBe(false);
  expect(reason).toBe('bad_signature');
});

test('tampered stamp rejected', () => {
  const store = makeStore();
  const { privateKey, publicKey } = generateAgentKeypair();
  const ch = generateChallenge(SERVER_SECRET);
  const [ok, reason] = verifyChallenge(SERVER_SECRET, {
    nonce: ch.nonce, timestamp: ch.timestamp, stamp: 'deadbeef',
    agent_public: publicKey, signature: solve(ch, privateKey),
  }, { nonceStore: store });
  expect(ok).toBe(false);
  expect(reason).toBe('invalid_stamp');
});

test('expired nonce rejected', () => {
  const store = makeStore();
  const { privateKey, publicKey } = generateAgentKeypair();
  const nonce = 'x'.repeat(43);
  const timestamp = Math.floor(Date.now() / 1000) - 9999;
  const st = stamp(SERVER_SECRET, nonce, timestamp);
  const [ok, reason] = verifyChallenge(SERVER_SECRET, {
    nonce, timestamp, stamp: st, agent_public: publicKey, signature: agentSign(privateKey, nonce),
  }, { ttl: 1, nonceStore: store });
  expect(ok).toBe(false);
  expect(reason).toBe('nonce_expired');
});

test('missing fields rejected', () => {
  const [ok, reason] = verifyChallenge(SERVER_SECRET, {
    nonce: '', timestamp: 0, stamp: '', agent_public: '', signature: '',
  }, { nonceStore: makeStore() });
  expect(ok).toBe(false);
  expect(reason).toBe('missing_fields');
});
