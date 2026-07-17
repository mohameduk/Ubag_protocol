'use strict';

const express = require('express');
const crypto = require('crypto');
const request = require('supertest');
const { ubag } = require('../src/middleware/express');
const { CREDENTIAL_HEADER, issueCredential } = require('../src/credential');
const { buildPopMessage } = require('../src/challenge');
const { generateIssuerKeypair, generateAgentKeypair, agentSign } = require('../src/keys');

const { privateKey: ISSUER_PRIV } = generateIssuerKeypair();

function popHeaders(cred, apriv, method = 'GET', path = '/hello', options = {}) {
  const host = options.host || 'testserver';
  const ts = options.ts || Math.floor(Date.now() / 1000);
  const jti = options.jti || crypto.randomBytes(16).toString('base64url');
  const msg = buildPopMessage(method, host, path, cred, ts, jti);
  return {
    [CREDENTIAL_HEADER]: cred,
    Host: host,
    'X-UBAG-PoP': agentSign(apriv, msg),
    'X-UBAG-PoP-TS': String(ts),
    'X-UBAG-PoP-JTI': jti,
    'X-UBAG-PoP-Version': '2',
  };
}

function makeApp(opts = {}) {
  const app = express();
  app.use(express.json());
  app.use(ubag({
    issuerKey: ISSUER_PRIV,
    serverSecret: 'test-server-secret-separate-from-issuer',
    allowSelfRegistration: true,
    siteMeta: { name: 'Test Store', type: 'Store' },
    ...opts,
  }));
  app.get('/hello', (req, res) => res.json({ msg: 'from origin app' }));
  return app;
}
const app = makeApp();

test('GET /.well-known/ubag.json returns discovery doc', async () => {
  const res = await request(app).get('/.well-known/ubag.json');
  expect(res.status).toBe(200);
  expect(res.body.ubag_version).toBe('1.0');
  expect(res.body.discovery.ubag_json).toMatch(/\/\.well-known\/ubag\.json$/);
});

test('GET /agents.json still served (legacy alias)', async () => {
  const res = await request(app).get('/agents.json');
  expect(res.status).toBe(200);
  expect(res.body.ubag_version).toBe('1.0');
});

test('credentialed agent with PoP gets JSON-LD (Branch B)', async () => {
  const agent = generateAgentKeypair();
  const token = issueCredential('ubag:test-agent', ISSUER_PRIV, { agentPublic: agent.publicKey });
  const res = await request(app).get('/hello').set(popHeaders(token, agent.privateKey));
  expect(res.status).toBe(200);
  expect(res.headers['x-ubag-branch']).toBe('B-AGENT');
  expect(res.body['ubag:agent']).toBe('ubag:test-agent');
});

test('JSON-LD content-type', async () => {
  const agent = generateAgentKeypair();
  const token = issueCredential('ubag:agent', ISSUER_PRIV, { agentPublic: agent.publicKey });
  const res = await request(app).get('/hello').set(popHeaders(token, agent.privateKey));
  expect(res.headers['content-type']).toMatch(/application\/ld\+json/);
});

// ── Proof-of-possession security regression tests ────────────────────────────

test('stolen credential without PoP is rejected (fail closed)', async () => {
  const agent = generateAgentKeypair();
  const token = issueCredential('ubag:victim', ISSUER_PRIV, { agentPublic: agent.publicKey });
  const res = await request(app).get('/hello').set(CREDENTIAL_HEADER, token);
  expect(res.status).toBe(401);
  expect(res.body.status).toBe('pop_required');
});

test('credential with attacker-key PoP is rejected', async () => {
  const victim = generateAgentKeypair();
  const attacker = generateAgentKeypair();
  const token = issueCredential('ubag:victim', ISSUER_PRIV, { agentPublic: victim.publicKey });
  const res = await request(app).get('/hello').set(popHeaders(token, attacker.privateKey));
  expect(res.status).toBe(401);
});

test('stale PoP timestamp is rejected', async () => {
  const agent = generateAgentKeypair();
  const token = issueCredential('ubag:test-agent', ISSUER_PRIV, { agentPublic: agent.publicKey });
  const res = await request(app).get('/hello').set(popHeaders(
    token, agent.privateKey, 'GET', '/hello', { ts: Math.floor(Date.now() / 1000) - 3600 }
  ));
  expect(res.status).toBe(401);
});

test('requirePop=false allows legacy bearer credential', async () => {
  const legacy = makeApp({ requirePop: false });
  const token = issueCredential('ubag:legacy', ISSUER_PRIV);
  const res = await request(legacy).get('/hello').set(CREDENTIAL_HEADER, token);
  expect(res.status).toBe(200);
  expect(res.headers['x-ubag-branch']).toBe('B-AGENT');
});

test('no serverSecret and no issuerKey refuses to start', () => {
  expect(() => ubag({ issuerKey: ISSUER_PRIV })).toThrow();
});

test('short serverSecret refuses to start', () => {
  expect(() => ubag({ issuerKey: ISSUER_PRIV, serverSecret: 'too-short' })).toThrow();
});

test('machine UA gets sandbox challenge (Branch C)', async () => {
  const res = await request(app).get('/hello').set('user-agent', 'python-requests/2.31').set('accept', '*/*');
  expect(res.status).toBe(429);
  expect(res.body.status).toBe('challenge_required');
  expect(res.body.ubag_challenge.nonce).toBeDefined();
  expect(res.body.ubag_challenge.algo).toBe('Ed25519');
});

test('human browser reaches app (Branch A)', async () => {
  const res = await request(app).get('/hello')
    .set('user-agent', 'Mozilla/5.0 (Windows NT 10.0) Chrome/120')
    .set('accept', 'text/html,application/xhtml+xml,*/*');
  expect(res.status).toBe(200);
  expect(res.body.msg).toBe('from origin app');
});

test('POST /ubag/verify issues a working credential', async () => {
  const agent = generateAgentKeypair();
  const ch = (await request(app).get('/hello').set('user-agent', 'curl/8.5').set('accept', '*/*')).body.ubag_challenge;
  const res = await request(app).post('/ubag/verify').send({
    nonce: ch.nonce, timestamp: ch.timestamp, stamp: ch.stamp,
    agent_public: agent.publicKey, signature: agentSign(agent.privateKey, ch.nonce),
  });
  expect(res.status).toBe(200);
  expect(res.body.status).toBe('credential_issued');
  const res2 = await request(app).get('/hello').set(popHeaders(res.body.credential, agent.privateKey));
  expect(res2.headers['x-ubag-branch']).toBe('B-AGENT');
});

test('wrong key rejected at verify', async () => {
  const agent = generateAgentKeypair();
  const other = generateAgentKeypair();
  const ch = (await request(app).get('/hello').set('user-agent', 'curl/8.5').set('accept', '*/*')).body.ubag_challenge;
  const res = await request(app).post('/ubag/verify').send({
    nonce: ch.nonce, timestamp: ch.timestamp, stamp: ch.stamp,
    agent_public: agent.publicKey, signature: agentSign(other.privateKey, ch.nonce),
  });
  expect(res.status).toBe(403);
  expect(res.body.reason).toBe('bad_signature');
});

test('replay rejected', async () => {
  const agent = generateAgentKeypair();
  const ch = (await request(app).get('/hello').set('user-agent', 'curl/8.5').set('accept', '*/*')).body.ubag_challenge;
  const payload = {
    nonce: ch.nonce, timestamp: ch.timestamp, stamp: ch.stamp,
    agent_public: agent.publicKey, signature: agentSign(agent.privateKey, ch.nonce),
  };
  await request(app).post('/ubag/verify').send(payload);
  const res = await request(app).post('/ubag/verify').send(payload);
  expect(res.status).toBe(403);
  expect(res.body.reason).toBe('nonce_already_used');
});

test('identity is not authorization by default', async () => {
  const guarded = makeApp({ allowSelfRegistration: false });
  const agent = generateAgentKeypair();
  const ch = (await request(guarded).get('/hello').set('user-agent', 'curl/8.5').set('accept', '*/*')).body.ubag_challenge;
  const res = await request(guarded).post('/ubag/verify').send({
    nonce: ch.nonce, timestamp: ch.timestamp, stamp: ch.stamp,
    agent_public: agent.publicKey, signature: agentSign(agent.privateKey, ch.nonce),
  });
  expect(res.status).toBe(202);
  expect(res.body.status).toBe('identity_verified');
  expect(res.body.credential).toBeUndefined();
});

test('authorization callback can restrict credential paths', async () => {
  const authorized = makeApp({
    allowSelfRegistration: false,
    authorizeAgent: () => ({ agentClass: 'authorized_agent', allowedPaths: ['/allowed'] }),
  });
  const agent = generateAgentKeypair();
  const ch = (await request(authorized).get('/hello').set('user-agent', 'curl/8.5').set('accept', '*/*')).body.ubag_challenge;
  const issued = await request(authorized).post('/ubag/verify').send({
    nonce: ch.nonce, timestamp: ch.timestamp, stamp: ch.stamp,
    agent_public: agent.publicKey, signature: agentSign(agent.privateKey, ch.nonce),
  });
  const denied = await request(authorized).get('/hello').set(popHeaders(issued.body.credential, agent.privateKey));
  expect(denied.status).toBe(403);
  expect(denied.body.status).toBe('path_denied');
});

test('PoP replay is rejected inside freshness window', async () => {
  const agent = generateAgentKeypair();
  const token = issueCredential('ubag:test-agent', ISSUER_PRIV, { agentPublic: agent.publicKey });
  const headers = popHeaders(token, agent.privateKey);
  expect((await request(app).get('/hello').set(headers)).status).toBe(200);
  expect((await request(app).get('/hello').set(headers)).status).toBe(401);
});

test('PoP is bound to host and query', async () => {
  const agent = generateAgentKeypair();
  const token = issueCredential('ubag:test-agent', ISSUER_PRIV, { agentPublic: agent.publicKey });
  const headers = popHeaders(token, agent.privateKey, 'GET', '/hello?view=one');
  expect((await request(app).get('/hello?view=two').set(headers)).status).toBe(401);
  expect((await request(app).get('/hello?view=one').set(headers)).status).toBe(200);

  const wrongHost = popHeaders(token, agent.privateKey, 'GET', '/hello', { host: 'other.example' });
  expect((await request(app).get('/hello').set(wrongHost).set('Host', 'testserver')).status).toBe(401);
});

test('revocation callback prevents Branch B access', async () => {
  const revoked = makeApp({ isCredentialRevoked: () => true });
  const agent = generateAgentKeypair();
  const token = issueCredential('ubag:revoked', ISSUER_PRIV, { agentPublic: agent.publicKey });
  const res = await request(revoked)
    .get('/hello')
    .set(popHeaders(token, agent.privateKey))
    .set('user-agent', 'node-fetch')
    .set('accept', '*/*');
  expect(res.status).toBe(429);
  expect(res.headers['x-ubag-branch']).toBe('C-SANDBOX');
});

test('verify endpoint applies rate and body-size limits', async () => {
  const limited = makeApp({ verifyRateLimit: 1, verifyBodyMaxBytes: 32 });
  await request(limited).post('/ubag/verify').send({});
  expect((await request(limited).post('/ubag/verify').send({})).status).toBe(429);

  const sized = makeApp({ verifyRateLimit: 0, verifyBodyMaxBytes: 8 });
  expect((await request(sized).post('/ubag/verify').send({ too: 'large' })).status).toBe(413);
});
