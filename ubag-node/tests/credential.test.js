'use strict';

const jwt = require('jsonwebtoken');
const {
  CREDENTIAL_HEADER,
  credentialPathAllowed,
  issueCredential,
  validateCredential,
} = require('../src/credential');
const { generateChallenge, verifyChallenge } = require('../src/challenge');
const { generateIssuerKeypair, generateAgentKeypair, agentId } = require('../src/keys');
const { AgentCredential } = require('../src/AgentCredential');

test('issue and validate roundtrip', () => {
  const { privateKey, publicKey } = generateIssuerKeypair();
  const token = issueCredential('ubag:agent1', privateKey);
  const claims = validateCredential(token, publicKey);
  expect(claims).not.toBeNull();
  expect(claims.sub).toBe('ubag:agent1');
  expect(claims.agent_class).toBe('self_asserted_agent');
  expect(claims.paths).toContain('/*');
  expect(claims.iss).toBe('https://ubagprotocol.com');
  expect(claims.aud).toBe('ubag-web');
  expect(claims.jti).toBeDefined();
});

test('wrong public key returns null', () => {
  const { privateKey } = generateIssuerKeypair();
  const other = generateIssuerKeypair();
  const token = issueCredential('a', privateKey);
  expect(validateCredential(token, other.publicKey)).toBeNull();
});

test('wrong issuer or audience returns null', () => {
  const { privateKey, publicKey } = generateIssuerKeypair();
  const token = issueCredential('a', privateKey, {
    issuer: 'https://issuer.example', audience: 'site-a',
  });
  expect(validateCredential(token, publicKey)).toBeNull();
  expect(validateCredential(token, publicKey, {
    issuer: 'https://issuer.example', audience: 'site-a',
  })).not.toBeNull();
});

test('credential paths are enforced as globs', () => {
  const claims = { paths: ['/products/*', '/health'] };
  expect(credentialPathAllowed(claims, '/products/42')).toBe(true);
  expect(credentialPathAllowed(claims, '/health')).toBe(true);
  expect(credentialPathAllowed(claims, '/admin')).toBe(false);
});

test('expired token returns null', () => {
  const { privateKey, publicKey } = generateIssuerKeypair();
  const token = jwt.sign({ sub: 'a' }, privateKey, { algorithm: 'ES256', expiresIn: -1 });
  expect(validateCredential(token, publicKey)).toBeNull();
});

test('credential binds agent key (cnf)', () => {
  const issuer = generateIssuerKeypair();
  const agent = generateAgentKeypair();
  const token = issueCredential(agentId(agent.publicKey), issuer.privateKey, { agentPublic: agent.publicKey });
  const claims = validateCredential(token, issuer.publicKey);
  expect(claims.cnf.jkt).toBe(agentId(agent.publicKey));
  expect(claims.cnf.pub).toBe(agent.publicKey);
});

test('CREDENTIAL_HEADER is X-UBAG-Credential', () => {
  expect(CREDENTIAL_HEADER).toBe('X-UBAG-Credential');
});

test('AgentCredential identity is its keypair', () => {
  const a = AgentCredential.generate({ owner: 'me@example.com' });
  expect(a.agentId).toMatch(/^ubag:/);
  const b = AgentCredential.load(a.export());
  expect(b.agentId).toBe(a.agentId);
});

test('full handshake: agent solves challenge, issuer mints credential', () => {
  const issuer = generateIssuerKeypair();
  const serverSecret = 's';
  const agent = AgentCredential.generate();
  const ch = generateChallenge(serverSecret);
  const sol = agent.solveChallenge(ch);
  const [ok, , aid] = verifyChallenge(serverSecret, sol);
  expect(ok).toBe(true);
  expect(aid).toBe(agent.agentId);
  const token = issueCredential(aid, issuer.privateKey, { agentPublic: agent.publicKey });
  agent.setCredential(token);
  const headers = agent.headers('GET', '/', { host: 'example.com' });
  expect(headers[CREDENTIAL_HEADER]).toBeDefined();
  expect(validateCredential(headers[CREDENTIAL_HEADER], issuer.publicKey).sub).toBe(agent.agentId);
});
