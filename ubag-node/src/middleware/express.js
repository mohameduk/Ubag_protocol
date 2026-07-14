'use strict';

const crypto = require('crypto');
const { fetch } = require('undici');
const { Branch, resolveBranch } = require('../routing');
const { CREDENTIAL_HEADER, issueCredential, validateCredential } = require('../credential');
const { generateChallenge, verifyChallenge, verifyPop } = require('../challenge');
const { issuerPublicFromPrivate, buildJwks } = require('../keys');
const { buildAgentsJson } = require('../agentsJson');

function ubag(options = {}) {
  const {
    origin = '',
    issuerKey = process.env.UBAG_ISSUER_KEY || '', // EC P-256 private PEM (mint + verify)
    issuerPublicKey = process.env.UBAG_ISSUER_PUBLIC || '', // verify-only sites
    serverSecret: serverSecretOpt = process.env.UBAG_SERVER_SECRET || '',
    siteMeta = {},
    credentialEndpoint = '',
    auditFn = null,
    onVerified = null,
    requirePop = true,
  } = options;

  const issuerPrivate = issuerKey;
  const issuerPublic = issuerPrivate ? issuerPublicFromPrivate(issuerPrivate) : issuerPublicKey;
  // HMAC key for stateless nonce stamping — the server signing to itself.
  // SECURITY: never fall back to a world-known constant. If nothing binds this
  // server's stamp key to a secret, refuse to start rather than let an attacker
  // forge nonce stamps under sha256("ubag-stamp").
  let serverSecret;
  if (serverSecretOpt) {
    serverSecret = serverSecretOpt;
  } else if (issuerPrivate) {
    serverSecret = crypto.createHash('sha256').update(issuerPrivate).digest('hex');
  } else {
    throw new Error(
      'UBAG: no serverSecret and no issuerKey configured. Refusing to start with a ' +
        'predictable HMAC stamp key. Set UBAG_SERVER_SECRET (or provide issuerKey).'
    );
  }

  const validateFn = (token) => validateCredential(token, issuerPublic);

  return async function ubagMiddleware(req, res, next) {
    const path = req.path || req.url;

    if (path === '/.well-known/ubag.json' || path === '/agents.json') { // /agents.json = legacy alias
      const host = (req.headers.host || '').split(':')[0];
      return res.json(buildAgentsJson(host, { credentialEndpoint }));
    }

    if (path === '/.well-known/jwks.json') {
      // Issuer public key, so any site can verify this issuer's credentials
      // without holding a secret (OAuth/OIDC model).
      if (!issuerPublic) return res.status(404).json({ error: 'no_issuer_key' });
      res.setHeader('Cache-Control', 'public, max-age=3600');
      return res.json(buildJwks(issuerPublic));
    }

    if (path === '/ubag/verify') {
      return handleVerify(req, res, { serverSecret, issuerPrivate, issuerPublic, credentialEndpoint, onVerified });
    }

    const ua = req.headers['user-agent'] || '';
    const accept = req.headers['accept'] || '';
    const token = req.headers[CREDENTIAL_HEADER.toLowerCase()] || req.headers[CREDENTIAL_HEADER];

    const branch = resolveBranch(ua, accept, token, validateFn);

    if (auditFn) {
      try {
        auditFn(branch, req);
      } catch {}
    }

    if (branch === Branch.AGENT) {
      const claims = validateFn(token);
      if (requirePop && !popOk(claims, req)) {
        // Credential is valid but the caller did not prove possession of the
        // bound agent key → fail closed. Defeats stolen-credential replay.
        res.setHeader('X-UBAG-Branch', 'B-DENIED');
        return res.status(401).json({
          status: 'pop_required',
          error:
            "Credential requires proof-of-possession. Sign 'METHOD PATH TIMESTAMP' " +
            'with your agent Ed25519 key and send X-UBAG-PoP (b64url signature) and ' +
            'X-UBAG-PoP-TS (unix seconds).',
        });
      }
      const host = (req.headers.host || '').split(':')[0];
      const payload = buildJsonLd(host, path, siteMeta, claims || {});
      res.setHeader('X-UBAG-Branch', 'B-AGENT');
      res.setHeader(CREDENTIAL_HEADER, token);
      return res.status(200).type('application/ld+json').json(payload);
    }

    if (branch === Branch.SANDBOX) {
      const challenge = generateChallenge(serverSecret);
      res.setHeader('X-UBAG-Branch', 'C-SANDBOX');
      return res.status(429).json({ status: 'challenge_required', ubag_challenge: challenge });
    }

    if (origin) {
      return proxyToOrigin(req, res, origin);
    }

    res.setHeader('X-UBAG-Branch', 'A-HUMAN');
    next();
  };
}

// ------------------------------------------------------------------

async function handleVerify(req, res, ctx) {
  const { serverSecret, issuerPrivate, issuerPublic, credentialEndpoint, onVerified } = ctx;
  let body;
  try {
    body = typeof req.body === 'object' && req.body ? req.body : JSON.parse(req.body);
  } catch {
    return res.status(400).json({ error: 'invalid_json' });
  }

  const [ok, reason, aid] = verifyChallenge(serverSecret, {
    nonce: body.nonce || '',
    timestamp: parseInt(body.timestamp || 0, 10),
    stamp: body.stamp || '',
    agent_public: body.agent_public || '',
    signature: body.signature || '',
  });

  if (!ok) return res.status(403).json({ status: 'failed', reason });

  if (!issuerPrivate) {
    return res.status(200).json({
      status: 'verified',
      agent_id: aid,
      credential_endpoint: credentialEndpoint,
      message: 'Identity verified. Obtain a credential from credential_endpoint.',
    });
  }

  const token = issueCredential(aid, issuerPrivate, { agentPublic: body.agent_public });

  if (onVerified) {
    try {
      onVerified(validateCredential(token, issuerPublic), req);
    } catch {}
  }

  return res.status(200).json({
    status: 'authorized',
    credential: token,
    header: CREDENTIAL_HEADER,
    instructions: `Include '${CREDENTIAL_HEADER}: ${token}' in all future requests.`,
  });
}

async function proxyToOrigin(req, res, origin) {
  const targetUrl = `${origin.replace(/\/$/, '')}${req.url}`;
  const skipHeaders = new Set(['connection', 'transfer-encoding', 'te', 'trailer', 'upgrade']);
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (!skipHeaders.has(k.toLowerCase())) headers[k] = v;
  }
  headers['host'] = (req.headers.host || '').split(':')[0];
  headers['x-forwarded-for'] = req.ip || 'unknown';
  headers['x-forwarded-proto'] = 'https';

  try {
    const upstream = await fetch(targetUrl, {
      method: req.method,
      headers,
      body: ['GET', 'HEAD'].includes(req.method) ? undefined : req,
      redirect: 'follow',
    });

    res.setHeader('X-UBAG-Branch', 'A-HUMAN');
    res.status(upstream.status);
    upstream.headers.forEach((v, k) => {
      if (!['transfer-encoding', 'connection'].includes(k.toLowerCase())) res.setHeader(k, v);
    });
    const buf = await upstream.arrayBuffer();
    res.send(Buffer.from(buf));
  } catch (err) {
    res.status(502).json({ error: 'upstream_error', detail: err.message });
  }
}

function popOk(claims, req) {
  // True if the request carries a valid proof-of-possession for the agent key
  // bound to the credential's `cnf` claim. A credential minted without a bound
  // key (no cnf.pub) cannot satisfy PoP and is rejected when requirePop is on.
  const agentPub = claims && claims.cnf && claims.cnf.pub;
  if (!agentPub) return false;
  return verifyPop(
    agentPub,
    req.method,
    req.path || req.url,
    req.headers['x-ubag-pop-ts'] || '0',
    req.headers['x-ubag-pop'] || ''
  );
}

function buildJsonLd(host, path, siteMeta, claims) {
  return {
    '@context': 'https://schema.org',
    '@type': siteMeta.type || 'WebSite',
    url: `https://${host}${path}`,
    name: siteMeta.name || host,
    ...siteMeta,
    'ubag:source': `https://${host}`,
    'ubag:served_at': Math.floor(Date.now() / 1000),
    'ubag:agent': claims.sub || 'unknown',
    'ubag:branch': 'B-AGENT',
  };
}

module.exports = { ubag };
