'use strict';

/**
 * AgentCredential — client helper for MCP agent developers.
 * An agent's identity IS its Ed25519 keypair; it solves a site challenge by signing
 * the nonce, then carries the credential the site/issuer returns.
 */
const { CREDENTIAL_HEADER } = require('./credential');
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
   * proof-of-possession (a fresh Ed25519 signature over "METHOD PATH TIMESTAMP").
   * The gateway checks this against the key bound in the credential's `cnf`
   * claim, so a stolen credential is useless without this agent's private key.
   * Pass the actual method and path of the call being made.
   */
  headers(method = 'GET', path = '/') {
    if (!this._token) {
      throw new Error('No credential yet — solve a site challenge and call setCredential() first.');
    }
    const ts = Math.floor(Date.now() / 1000);
    const message = `${String(method).toUpperCase()} ${path} ${ts}`;
    return {
      [CREDENTIAL_HEADER]: this._token,
      'X-UBAG-PoP': agentSign(this.privateKey, message),
      'X-UBAG-PoP-TS': String(ts),
    };
  }
}

module.exports = { AgentCredential };
