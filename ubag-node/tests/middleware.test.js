'use strict';

const express = require('express');
const request = require('supertest');
const { ubag } = require('../src/middleware/express');
const { CREDENTIAL_HEADER, issueCredential } = require('../src/credential');
const { generateIssuerKeypair, generateAgentKeypair, agentSign } = require('../src/keys');

const { privateKey: ISSUER_PRIV } = generateIssuerKeypair();

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use(ubag({ issuerKey: ISSUER_PRIV, siteMeta: { name: 'Test Store', type: 'Store' } }));
  app.get('/hello', (req, res) => res.json({ msg: 'from origin app' }));
  return app;
}
const app = makeApp();

test('GET /agents.json returns discovery doc', async () => {
  const res = await request(app).get('/agents.json');
  expect(res.status).toBe(200);
  expect(res.body.ubag_version).toBe('1.0');
});

test('credentialed agent gets JSON-LD (Branch B)', async () => {
  const token = issueCredential('ubag:test-agent', ISSUER_PRIV);
  const res = await request(app).get('/hello').set(CREDENTIAL_HEADER, token);
  expect(res.status).toBe(200);
  expect(res.headers['x-ubag-branch']).toBe('B-AGENT');
  expect(res.body['ubag:agent']).toBe('ubag:test-agent');
});

test('JSON-LD content-type', async () => {
  const token = issueCredential('ubag:agent', ISSUER_PRIV);
  const res = await request(app).get('/hello').set(CREDENTIAL_HEADER, token);
  expect(res.headers['content-type']).toMatch(/application\/ld\+json/);
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
  expect(res.body.status).toBe('authorized');
  const res2 = await request(app).get('/hello').set(CREDENTIAL_HEADER, res.body.credential);
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
