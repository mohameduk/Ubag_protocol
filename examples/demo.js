'use strict';
/**
 * UBAG Web Layer — end-to-end demo (Node / Express).
 *
 *     npm install --prefix ubag-node
 *     node examples/demo.js
 *
 * Starts a UBAG-protected Express site on an ephemeral port and walks one
 * autonomous agent through the entire handshake:
 *
 *     blocked  ->  challenged  ->  signs the nonce  ->  credentialed  ->  JSON-LD
 *
 * Then shows the JWKS any other site would use to verify this issuer's credentials.
 */
const path = require('path');
const { createRequire } = require('module');
// Resolve express/undici and the SDK from ubag-node's installed modules, so the
// demo runs from anywhere once `npm install --prefix ubag-node` has been run.
const req = createRequire(path.join(__dirname, '..', 'ubag-node', 'package.json'));
const express = req('express');
const { fetch } = req('undici');
const { ubag, AgentCredential, generateIssuerKeypair } = req('./src');

const { privateKey: ISSUER_PRIVATE } = generateIssuerKeypair();

const app = express();
app.use(express.json());
app.use(ubag({
  issuerKey: ISSUER_PRIVATE,
  siteMeta: { name: 'Acme Widgets', type: 'Store', description: 'We sell premium widgets' },
}));
app.get('/', (req, res) => res.type('html').send('<h1>Acme Widgets</h1><p>We sell premium widgets.</p>'));

const AGENT_UA = { 'user-agent': 'node-fetch ubag-demo-agent' };
const step = (t) => console.log('\n' + '='.repeat(66) + '\n' + t + '\n' + '='.repeat(66));

(async () => {
  const server = app.listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    // 0 — discovery
    step('0. Agent discovers the site via /.well-known/ubag.json');
    console.log(await (await fetch(`${base}/.well-known/ubag.json`)).json());

    // 1 — cold request is challenged
    step('1. Unknown agent requests /  ->  Branch C (challenge)');
    let r = await fetch(`${base}/`, { headers: AGENT_UA });
    console.log('status:', r.status, '| branch:', r.headers.get('x-ubag-branch'));
    const { ubag_challenge: challenge } = await r.json();
    console.log('nonce:', challenge.nonce.slice(0, 24), '...  algo:', challenge.algo);

    // 2 — agent signs the nonce with its Ed25519 private key
    step('2. Agent signs the nonce with its Ed25519 private key');
    const agent = AgentCredential.generate({ owner: 'demo@agent.dev' });
    console.log('agent id:', agent.agentId);
    const solution = agent.solveChallenge(challenge);
    console.log('signature:', solution.signature.slice(0, 24), '...');

    // 3 — post the solution, issuer mints a credential
    step('3. POST /ubag/verify  ->  issuer mints a credential');
    r = await fetch(`${base}/ubag/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(solution),
    });
    const vr = await r.json();
    agent.setCredential(vr.credential);
    console.log('status:', r.status, vr.status, '| credential:', vr.credential.slice(0, 32), '...');

    // 4 — re-request WITH the credential, get clean JSON-LD
    step('4. Agent requests /  WITH credential  ->  Branch B (JSON-LD)');
    r = await fetch(`${base}/`, { headers: { ...AGENT_UA, ...agent.headers() } });
    console.log('status:', r.status, '| branch:', r.headers.get('x-ubag-branch'));
    console.log(await r.json());

    // 5 — any other site verifies this issuer's credentials via JWKS, no shared secret
    step('5. /.well-known/jwks.json  ->  public key for cross-site verification');
    console.log(await (await fetch(`${base}/.well-known/jwks.json`)).json());

    console.log('\nDone: blocked -> challenged -> signed -> credentialed -> JSON-LD.\n');
  } finally {
    server.close();
  }
})();
