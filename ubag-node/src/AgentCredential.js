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

  headers() {
    if (!this._token) {
      throw new Error('No credential yet — solve a site challenge and call setCredential() first.');
    }
    return { [CREDENTIAL_HEADER]: this._token };
  }
}

module.exports = { AgentCredential };
