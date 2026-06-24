'use strict';

const MACHINE_UA = /python-httpx|python-requests|aiohttp|curl\/|wget\/|go-http-client|java\/|okhttp|axios|node-fetch|got\/|undici|libwww|mechanize|scrapy|selenium|playwright|puppeteer|headlesschrome|GPTBot|ClaudeBot|PerplexityBot|anthropic-ai|Googlebot|bingbot|DuckDuckBot|Baiduspider|YandexBot|facebookexternalhit|Twitterbot/i;
const BROWSER_ACCEPT = /text\/html/i;
const BROWSER_UA     = /Mozilla|Chrome|Safari|Firefox|Edge/i;

const Branch = {
  HUMAN:   'A-HUMAN',
  AGENT:   'B-AGENT',
  SANDBOX: 'C-SANDBOX',
};

function isMachine(userAgent, accept) {
  if (MACHINE_UA.test(userAgent)) return true;
  // UA claims browser but no text/html Accept — library impersonation
  if (BROWSER_UA.test(userAgent) && !BROWSER_ACCEPT.test(accept)) return true;
  return false;
}

function resolveBranch(userAgent, accept, credentialToken, validateFn) {
  if (credentialToken) {
    const claims = validateFn(credentialToken);
    if (claims) return Branch.AGENT;
  }
  if (isMachine(userAgent, accept)) return Branch.SANDBOX;
  return Branch.HUMAN;
}

module.exports = { Branch, resolveBranch, isMachine };
