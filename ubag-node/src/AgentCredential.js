'use strict';

/**
 * AgentCredential — client helper for MCP agent developers.
 * An agent's identity IS its Ed25519 keypair; it solves a site challenge by signing
 * the nonce, then carries the credential the site/issuer returns.
 */
const { CREDENTIAL_HEADER } = require('./credential');
const crypto = require('crypto');
const { buildPopMessage } = require('./challenge');
const { generateAgentKeypair, agentSign, agentId } = require('./keys');

class AgentCredential {
  constructor(privateKey, publicKey, { owner = '', agentClass = 'mcp_agent' } = {}) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.owner = owner;
    this.agentClass = agentClass;
    this.agentId = agentId(publicKey);
    this._token = null;
  }

  static generate({ owner = '', agentClass = 'mcp_agent' } = {}) {
    const { privateKey, publicKey } = generateAgentKeypair();
    return new AgentCredential(privateKey, publicKey, { owner, agentClass });
  }

  export() {
    return {
      privateKey: this.privateKey,
      publicKey: this.publicKey,
      owner: this.owner,
      agentClass: this.agentClass,
    };
  }

  static load(d) {
    return new AgentCredential(d.privateKey, d.publicKey, {
      owner: d.owner,
      agentClass: d.agentClass,
    });
  }

  /** Sign a site's nonce challenge. Returns the body to POST to /ubag/verify. */
  solveChallenge(ch) {
    return {
      nonce: ch.nonce,
      timestamp: ch.timestamp,
      stamp: ch.stamp,
      agent_public: this.publicKey,
      signature: agentSign(this.privateKey, ch.nonce),
    };
  }

  setCredential(token) {
    this._token = token;
  }

  /**
   * Headers for a credentialed request: the credential PLUS a per-request
   * v2 proof-of-possession bound to method, host, path+query, credential,
   * timestamp, and a one-time identifier. Pass an absolute URL or supply host.
   */
  headers(method = 'GET', path = '/', { host = '' } = {}) {
    if (!this._token) {
      throw new Error('No credential yet — solve a site challenge and call setCredential() first.');
    }
    let target = path;
    try {
      const parsed = new URL(path);
      host = parsed.host;
      target = `${parsed.pathname}${parsed.search}`;
    } catch {}
    if (!host) throw new Error('host is required when path is not an absolute URL');
    const ts = Math.floor(Date.now() / 1000);
    const jti = crypto.randomBytes(16).toString('base64url');
    const message = buildPopMessage(method, host, target, this._token, ts, jti);
    return {
      [CREDENTIAL_HEADER]: this._token,
      'X-UBAG-PoP': agentSign(this.privateKey, message),
      'X-UBAG-PoP-TS': String(ts),
      'X-UBAG-PoP-JTI': jti,
      'X-UBAG-PoP-Version': '2',
    };
  }
}

module.exports = { AgentCredential };
