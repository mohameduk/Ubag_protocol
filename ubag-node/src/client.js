'use strict';

/**
 * One-call scoped retrieval, built on the primitives AgentCredential has.
 *
 * AgentCredential handles identity: generate a keypair, solve a challenge,
 * hold a credential, produce proof-of-possession headers. What it does not do
 * is the HTTP round trip, and the round trip is where adoption dies. By hand
 * that means: request the page, recognise the 429, pull the challenge out of
 * the body, solve it, POST to /ubag/verify, find the credential header, store
 * it, build the query, attach headers, notice when the credential expires, and
 * do it again. Forty lines to save tokens the caller has not yet noticed
 * spending.
 *
 *     const { Agent } = require('ubag');
 *
 *     const agent = Agent.generate();
 *     const answer = await agent.fields('https://shop.example.com/p/3391',
 *                                       ['offers.price', 'offers.availability']);
 *
 * Measured on 63 ground-truth questions through a live gateway: 12.5x fewer
 * input tokens on gpt-4o-mini, 12.1x on gemini-2.5-flash, accuracy unchanged.
 *
 * Uses global fetch, so Node 18 or newer. No dependencies.
 */

const { AgentCredential } = require('./AgentCredential');
const { CREDENTIAL_HEADER } = require('./credential');

const LEGACY_CREDENTIAL_HEADER = 'X-Web-UBAG-Credential';

// Re-identify on this clock rather than waiting to be refused. An expired
// credential drops the caller onto the unauthorized branch, where the reply is
// a challenge that looks like an answer: readable JSON, no error, no fields.
const REIDENTIFY_AFTER_MS = 900 * 1000;

class ChallengeFailed extends Error {}
class NotIdentified extends Error {}

class Agent {
  constructor(credential, { timeoutMs = 30000 } = {}) {
    this.credential = credential;
    this.timeoutMs = timeoutMs;
    this._identifiedAt = 0;
    this._origin = '';
  }

  /** A fresh Ed25519 identity. The private key never leaves this process. */
  static generate(opts = {}) {
    return new Agent(AgentCredential.generate(opts), opts);
  }

  /** Reuse a previously exported identity, so the agent ref stays stable. */
  static load(data, opts = {}) {
    return new Agent(AgentCredential.load(data), opts);
  }

  get agentId() {
    return this.credential.agentId;
  }

  export() {
    return this.credential.export();
  }

  async _fetch(url, init = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      return await fetch(url, { ...init, signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Complete the challenge-response for this site.
   *
   * Called automatically. Worth calling directly to fail early against a site
   * that does not speak UBAG.
   */
  async identify(url) {
    const origin = new URL(url).origin;

    const probe = await this._fetch(url, { headers: { Accept: 'application/json' } });
    if (probe.status !== 429) {
      throw new ChallengeFailed(
        `expected a challenge, got ${probe.status} on branch `
        + `${probe.headers.get('X-UBAG-Branch') || 'unknown'}`,
      );
    }

    const body = await probe.json();
    const challenge = body.ubag_challenge || body;
    const verified = await this._fetch(`${origin}/ubag/verify`, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify(this.credential.solveChallenge(challenge)),
    });
    if (verified.status !== 200) {
      throw new ChallengeFailed(
        `verify returned ${verified.status}: ${(await verified.text()).slice(0, 200)}`,
      );
    }

    const token = verified.headers.get(CREDENTIAL_HEADER)
      || verified.headers.get(LEGACY_CREDENTIAL_HEADER);
    if (!token) throw new ChallengeFailed('verify succeeded but returned no credential header');

    this.credential.setCredential(token);
    this._identifiedAt = Date.now();
    this._origin = origin;
  }

  async _get(url, params) {
    const target = new URL(url);
    const stale = Date.now() - this._identifiedAt > REIDENTIFY_AFTER_MS;
    if (stale || this._origin !== target.origin) await this.identify(url);

    let path = target.pathname || '/';
    if (params) path += `?${params}`;
    const full = `${this._origin}${path}`;

    const response = await this._fetch(full, {
      headers: {
        Accept: 'application/json',
        ...this.credential.headers('GET', full),
      },
    });

    const branch = response.headers.get('X-UBAG-Branch') || 'unknown';
    if (branch !== 'B-AGENT') {
      throw new NotIdentified(`reached branch ${branch} with status ${response.status}`);
    }
    if (response.status >= 400) {
      // An error is not a statement about the resource's contents, and must
      // never be returned as though it were one.
      throw new NotIdentified(`${response.status}: ${(await response.text()).slice(0, 200)}`);
    }
    return response.json();
  }

  /**
   * Ask a page for specific typed fields.
   *
   * Anything the page cannot answer comes back under ubag:unresolved rather
   * than being silently omitted, so absence stays distinguishable from a
   * negative answer.
   */
  async fields(url, fields) {
    const joined = encodeURIComponent(fields.join(',')).replace(/%2C/g, ',');
    return this._get(url, `ubag.fields=${joined}`);
  }

  /** What this page can answer, without answering. Cacheable per URL. */
  async manifest(url) {
    return this._get(url, 'ubag.manifest=1');
  }

  /** The whole payload, for when the answer really is the whole page. */
  async full(url) {
    return this._get(url, '');
  }
}

module.exports = { Agent, ChallengeFailed, NotIdentified };
