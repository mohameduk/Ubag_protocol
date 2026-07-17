'use strict';

const { fetch } = require('undici');
const { Branch, resolveBranch } = require('../routing');
const {
  CREDENTIAL_HEADER,
  DEFAULT_AUDIENCE,
  DEFAULT_ISSUER,
  credentialPathAllowed,
  issueCredential,
  validateCredential,
} = require('../credential');
const { MemoryReplayStore, generateChallenge, verifyChallenge, verifyPop } = require('../challenge');
const { issuerPublicFromPrivate, buildJwks } = require('../keys');
const { buildAgentsJson } = require('../agentsJson');
const { buildJsonldResponse } = require('../sux');
const { TTLCache } = require('../cache');

class SlidingWindowLimiter {
  constructor(limit, windowSeconds) {
    this.limit = limit;
    this.windowSeconds = windowSeconds;
    this.events = new Map();
  }

  allow(key) {
    if (this.limit <= 0) return true;
    const now = Date.now() / 1000;
    const events = (this.events.get(key) || []).filter((value) => value > now - this.windowSeconds);
    if (events.length >= this.limit) {
      this.events.set(key, events);
      return false;
    }
    events.push(now);
    this.events.set(key, events);
    return true;
  }
}

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
    authorizeAgent = null,
    allowSelfRegistration = false,
    isCredentialRevoked = null,
    credentialIssuer = DEFAULT_ISSUER,
    credentialAudience = DEFAULT_AUDIENCE,
    credentialKid = 'ubag-issuer-1',
    nonceStore = null,
    popStore = null,
    verifyRateLimit = 30,
    verifyRateWindow = 60,
    verifyBodyMaxBytes = 16384,
    requirePop = true,
    autoExtract = true,
    extractCacheTtl = 300,
    extractCacheSize = 256,
    includeMarkdown = true,
    contentMaxChars = 20000,
  } = options;

  // Tier 1 auto-extraction: harvest the origin's declared structured data for
  // Branch B instead of requiring hand-written siteMeta. Only when an origin is
  // configured; siteMeta always overrides. Fetched HTML is cached (LRU + TTL).
  const htmlCache = new TTLCache(extractCacheSize, extractCacheTtl);

  const issuerPrivate = issuerKey;
  const issuerPublic = issuerPrivate ? issuerPublicFromPrivate(issuerPrivate) : issuerPublicKey;
  // Separate HMAC key for nonce stamping; never derive it from the issuer key.
  const serverSecret = serverSecretOpt;
  if (!serverSecret) {
    throw new Error(
      'UBAG: serverSecret is required. Set UBAG_SERVER_SECRET or pass a separate strong serverSecret.'
    );
  }
  if (serverSecret.length < 32) {
    throw new Error('UBAG: serverSecret must be at least 32 characters.');
  }

  const nonceReplayStore = nonceStore || new MemoryReplayStore();
  const popReplayStore = popStore || new MemoryReplayStore();
  const verifyLimiter = new SlidingWindowLimiter(verifyRateLimit, verifyRateWindow);
  const validateFn = (token) => {
    const claims = validateCredential(token, issuerPublic, {
      issuer: credentialIssuer,
      audience: credentialAudience,
    });
    if (claims && isCredentialRevoked) {
      try {
        if (isCredentialRevoked(claims)) return null;
      } catch {
        return null;
      }
    }
    return claims;
  };

  return async function ubagMiddleware(req, res, next) {
    const path = req.path || req.url;

    if (path === '/.well-known/ubag.json' || path === '/agents.json') { // /agents.json = legacy alias
      const host = (req.headers.host || '').split(':')[0];
      return res.json(buildAgentsJson(host, { credentialEndpoint }));
    }

    if (path === '/.well-known/jwks.json') {
      // Issuer public key for sites that explicitly trust this issuer.
      if (!issuerPublic) return res.status(404).json({ error: 'no_issuer_key' });
      res.setHeader('Cache-Control', 'public, max-age=3600');
      return res.json(buildJwks(issuerPublic, credentialKid));
    }

    if (path === '/ubag/verify') {
      return handleVerify(req, res, {
        serverSecret,
        issuerPrivate,
        credentialEndpoint,
        onVerified,
        authorizeAgent,
        allowSelfRegistration,
        credentialIssuer,
        credentialAudience,
        credentialKid,
        nonceStore: nonceReplayStore,
        verifyLimiter,
        verifyBodyMaxBytes,
        validateFn,
      });
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
      if (!credentialPathAllowed(claims, req.path || String(req.url).split('?')[0])) {
        res.setHeader('X-UBAG-Branch', 'B-DENIED');
        return res.status(403).json({
          status: 'path_denied',
          error: 'Credential does not grant this path.',
        });
      }
      if (requirePop && !popOk(claims, req, token, popReplayStore)) {
        // Credential is valid but the caller did not prove possession of the
        // bound agent key → fail closed. Defeats stolen-credential replay.
        res.setHeader('X-UBAG-Branch', 'B-DENIED');
        return res.status(401).json({
          status: 'pop_required',
          error:
            'Credential requires UBAG-POP-V2. Send X-UBAG-PoP, X-UBAG-PoP-TS, ' +
            'and X-UBAG-PoP-JTI for the exact request target.',
        });
      }
      const host = (req.headers.host || '').split(':')[0];
      const html = await originHtml(origin, path, { autoExtract, cache: htmlCache });
      const payload = buildJsonldResponse(host, path, siteMeta, claims || {}, html, {
        includeMarkdown,
        contentMaxChars,
      });
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
  const {
    serverSecret,
    issuerPrivate,
    credentialEndpoint,
    onVerified,
    authorizeAgent,
    allowSelfRegistration,
    credentialIssuer,
    credentialAudience,
    credentialKid,
    nonceStore,
    verifyLimiter,
    verifyBodyMaxBytes,
    validateFn,
  } = ctx;
  if (!verifyLimiter.allow(req.ip || req.socket.remoteAddress || 'unknown')) {
    return res.status(429).json({ error: 'rate_limited' });
  }
  const contentLength = Number(req.headers['content-length'] || 0);
  if (!Number.isFinite(contentLength) || contentLength < 0) {
    return res.status(400).json({ error: 'invalid_content_length' });
  }
  if (contentLength > verifyBodyMaxBytes) {
    return res.status(413).json({ error: 'request_too_large' });
  }
  let body;
  try {
    body = typeof req.body === 'object' && req.body ? req.body : JSON.parse(req.body);
    if (!body || Array.isArray(body) || Buffer.byteLength(JSON.stringify(body)) > verifyBodyMaxBytes) {
      return res.status(413).json({ error: 'request_too_large' });
    }
  } catch {
    return res.status(400).json({ error: 'invalid_json' });
  }

  const timestamp = Number(body.timestamp);
  if (!Number.isInteger(timestamp)) {
    return res.status(400).json({ error: 'invalid_timestamp' });
  }

  const [ok, reason, aid] = verifyChallenge(serverSecret, {
    nonce: body.nonce || '',
    timestamp,
    stamp: body.stamp || '',
    agent_public: body.agent_public || '',
    signature: body.signature || '',
  }, { nonceStore });

  if (!ok) return res.status(403).json({ status: 'failed', reason });

  if (!issuerPrivate) {
    return res.status(200).json({
      status: 'identity_verified',
      agent_id: aid,
      credential_endpoint: credentialEndpoint,
      message: 'Identity verified. Obtain a credential from credential_endpoint.',
    });
  }

  let authorization = null;
  if (authorizeAgent) {
    const result = await authorizeAgent({ agentId: aid, agentPublic: body.agent_public }, req);
    if (result === true) {
      authorization = { agentClass: 'authorized_agent', allowedPaths: ['/*'] };
    } else if (result && typeof result === 'object') {
      authorization = result;
    }
  } else if (allowSelfRegistration) {
    authorization = { agentClass: 'self_asserted_agent', allowedPaths: ['/*'] };
  }

  if (!authorization) {
    return res.status(202).json({
      status: 'identity_verified',
      agent_id: aid,
      message: 'Identity verified; site authorization is required before credential issuance.',
    });
  }

  const token = issueCredential(aid, issuerPrivate, {
    agentPublic: body.agent_public,
    agentClass: authorization.agentClass || 'authorized_agent',
    allowedPaths: authorization.allowedPaths || ['/*'],
    issuer: credentialIssuer,
    audience: credentialAudience,
    kid: credentialKid,
  });

  if (onVerified) {
    try {
      onVerified(validateFn(token), req);
    } catch {}
  }

  return res.status(200).json({
    status: 'credential_issued',
    credential: token,
    header: CREDENTIAL_HEADER,
    instructions:
      `Include '${CREDENTIAL_HEADER}: ${token}' plus a v2 request-bound ` +
      'proof of possession in future requests.',
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

function popOk(claims, req, token, replayStore) {
  // True if the request carries a valid proof-of-possession for the agent key
  // bound to the credential's `cnf` claim. A credential minted without a bound
  // key (no cnf.pub) cannot satisfy PoP and is rejected when requirePop is on.
  const agentPub = claims && claims.cnf && claims.cnf.pub;
  if (!agentPub) return false;
  return verifyPop(
    agentPub,
    req.method,
    String(req.headers.host || '').toLowerCase(),
    req.originalUrl || req.url,
    token,
    req.headers['x-ubag-pop-ts'] || '0',
    req.headers['x-ubag-pop-jti'] || '',
    req.headers['x-ubag-pop'] || '',
    { replayStore }
  );
}

async function originHtml(origin, path, { autoExtract, cache, fetchImpl = fetch }) {
  // Fetch the origin's HTML for `path` so Tier 1 can harvest its declared
  // structured data. Cached (bounded LRU + TTL). Returns null — and the builder
  // falls back to siteMeta only — when extraction is off, no origin is set, the
  // fetch fails, or the response is not HTML. Negatives are cached too, to avoid
  // refetch storms. `fetchImpl` is injectable for testing; defaults to undici.
  if (!autoExtract || !origin) return null;
  const cached = cache.get(path);
  if (cached !== undefined) return cached || null; // '' is a cached negative
  let html = '';
  try {
    const url = `${origin.replace(/\/$/, '')}/${path.replace(/^\//, '')}`;
    const resp = await fetchImpl(url, { headers: { accept: 'text/html' } });
    const ctype = resp.headers.get('content-type') || '';
    html = resp.status === 200 && ctype.includes('html') ? await resp.text() : '';
  } catch {
    html = '';
  }
  cache.set(path, html);
  return html || null;
}

module.exports = { ubag, originHtml };
