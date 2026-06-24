'use strict';

const { Branch, resolveBranch } = require('../src/routing');
const { issueCredential, validateCredential } = require('../src/credential');
const { generateIssuerKeypair } = require('../src/keys');

const { privateKey: ISSUER_PRIV, publicKey: ISSUER_PUB } = generateIssuerKeypair();
const validateFn = (token) => validateCredential(token, ISSUER_PUB);

test('valid credential routes to B-AGENT', () => {
  const token = issueCredential('ubag:agent', ISSUER_PRIV);
  expect(resolveBranch('python-httpx/0.27', '*/*', token, validateFn)).toBe(Branch.AGENT);
});

test('machine UA without credential routes to C-SANDBOX', () => {
  expect(resolveBranch('python-requests/2.31', '*/*', null, validateFn)).toBe(Branch.SANDBOX);
});

test('curl routes to C-SANDBOX', () => {
  expect(resolveBranch('curl/8.5.0', '*/*', null, validateFn)).toBe(Branch.SANDBOX);
});

test('GPTBot routes to C-SANDBOX', () => {
  expect(resolveBranch('GPTBot/1.0', '*/*', null, validateFn)).toBe(Branch.SANDBOX);
});

test('browser with text/html accept routes to A-HUMAN', () => {
  expect(
    resolveBranch('Mozilla/5.0 (Windows NT 10.0) Chrome/120', 'text/html,application/xhtml+xml,*/*', null, validateFn)
  ).toBe(Branch.HUMAN);
});

test('browser without text/html accept routes to C-SANDBOX', () => {
  expect(resolveBranch('Mozilla/5.0 Chrome/120', 'application/json', null, validateFn)).toBe(Branch.SANDBOX);
});

test('no UA routes to A-HUMAN (fail open)', () => {
  expect(resolveBranch('', 'text/html', null, validateFn)).toBe(Branch.HUMAN);
});

test('expired credential routes to C-SANDBOX', () => {
  const jwt = require('jsonwebtoken');
  const expired = jwt.sign({ sub: 'agent' }, ISSUER_PRIV, { algorithm: 'ES256', expiresIn: -1 });
  expect(resolveBranch('python-httpx', '*/*', expired, validateFn)).toBe(Branch.SANDBOX);
});
