'use strict';

/**
 * Scoped retrieval: return the answer, not the page.
 *
 * This is the half of UBAG that is free and meant to be everywhere. Any site
 * can implement it without us, and should: the value of an agent identity
 * grows with the number of sites that answer one, so an endpoint reachable
 * only through a single vendor would be worth nothing to anybody.
 *
 * An agent asking a page what something costs receives the whole page today,
 * because the page has no way to answer a narrower question. Measured live
 * against two providers on 63 ground-truth questions:
 *
 *     fetch and extract the page   2,695 input tokens   41/63 correct
 *     ask for the fields             215 input tokens   41/63 correct
 *
 * 12.5x on gpt-4o-mini, 12.1x on gemini-2.5-flash, accuracy unchanged.
 *
 * Two rules, both load-bearing:
 *
 * 1. NO MODEL RUNS HERE. Resolution is deterministic lookup over the
 *    publisher's own structured data. An endpoint that interpreted natural
 *    language would move the caller's inference cost onto the publisher,
 *    which is the cost this exists to remove.
 *
 * 2. MISSES ARE REPORTED, NEVER GUESSED. Unresolvable fields come back under
 *    ubag:unresolved. An agent must be able to tell "this resource says
 *    nothing about price" from "the price is nothing".
 */

// schema.org containers holding the interesting leaves one level down.
const TRANSPARENT = new Set(['@graph', 'itemListElement', 'mainEntity', 'mainEntityOfPage']);

const MAX_FIELDS = 32;
const MAX_VALUE_CHARS = 2000;

function isLeaf(v) {
  return v === null || ['string', 'number', 'boolean'].includes(typeof v);
}

function keep(v) {
  if (!isLeaf(v)) return false;
  return !(typeof v === 'string' && v.length > MAX_VALUE_CHARS);
}

/** Walk, collapsing lists so offers.price finds offers[0].price. */
function* walk(node, prefix = '') {
  if (Array.isArray(node)) {
    for (const item of node) yield* walk(item, prefix);
    return;
  }
  if (node && typeof node === 'object') {
    for (const [key, value] of Object.entries(node)) {
      if (key.startsWith('@') && key !== '@type' && key !== '@id') {
        if (TRANSPARENT.has(key)) yield* walk(value, prefix);
        continue;
      }
      const path = prefix ? `${prefix}.${key}` : key;
      if (TRANSPARENT.has(key)) {
        yield* walk(value, prefix);
      } else {
        yield [path, value];
        yield* walk(value, path);
      }
    }
  }
}

/** Walk with list position in the path, for openingHoursSpecification[1].opens. */
function* walkIndexed(node, prefix = '') {
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i += 1) yield* walkIndexed(node[i], `${prefix}[${i}]`);
    return;
  }
  if (node && typeof node === 'object') {
    for (const [key, value] of Object.entries(node)) {
      if (key.startsWith('@') && key !== '@type' && key !== '@id') {
        if (TRANSPARENT.has(key)) yield* walkIndexed(value, prefix);
        continue;
      }
      const path = prefix ? `${prefix}.${key}` : key;
      if (TRANSPARENT.has(key)) {
        yield* walkIndexed(value, prefix);
      } else {
        yield [path, value];
        yield* walkIndexed(value, path);
      }
    }
  }
}

/**
 * path -> value over the parts of a payload carrying typed facts.
 *
 * Publisher-declared structured data is searched first and wins ties: it is
 * the site's own assertion about itself, and the only part of a page authored
 * to be machine-read.
 */
function indexFields(payload) {
  const idx = {};
  const sources = [payload.structured_data || [], payload.meta || {}];
  for (const source of sources) {
    for (const [path, value] of walk(source)) {
      if (!keep(value)) continue;
      const lowered = path.toLowerCase();
      if (!(lowered in idx)) idx[lowered] = value;
      const leaf = lowered.split('.').pop();
      if (!(leaf in idx)) idx[leaf] = value;
    }
  }
  return idx;
}

/** Built on demand, so ordinary requests never pay for it. */
function positionalIndex(payload) {
  const idx = {};
  // Each JSON-LD block walked separately, or a caller would have to write
  // [0].openingHoursSpecification[1] and know how many script tags a page has.
  const sources = [...(payload.structured_data || []), payload.meta || {}];
  for (const source of sources) {
    for (const [path, value] of walkIndexed(source)) {
      if (!keep(value)) continue;
      const lowered = path.toLowerCase();
      if (!(lowered in idx)) idx[lowered] = value;
    }
  }
  return idx;
}

/** What this resource can answer, without answering anything. */
function manifest(payload) {
  const idx = indexFields(payload);
  const types = new Set();
  for (const [path, value] of walk(payload.structured_data || [])) {
    if (path.toLowerCase().endsWith('@type') && typeof value === 'string') types.add(value);
  }
  return {
    '@context': 'https://schema.org',
    'ubag:protocol': 'S-UX/1.1',
    url: payload['ubag:source'] || '',
    'ubag:types': [...types].sort(),
    'ubag:fields': Object.keys(idx).sort(),
    'ubag:full_payload': '?ubag=full',
  };
}

/** Return only the requested typed fields, plus the subject they belong to. */
function resolve(payload, fields) {
  const idx = indexFields(payload);
  const out = {
    '@context': 'https://schema.org',
    'ubag:protocol': 'S-UX/1.1',
    url: payload['ubag:source'] || '',
  };

  // Always name the subject, even when nobody asked.
  //
  // {"offers.price": "862.00"} is correct and unusable: an agent that asked
  // what a named product costs cannot tell whether this price belongs to it.
  // Handed exactly that, a model answered NOT PRESENT rather than risk
  // attributing a price to the wrong item. That instinct is right and the
  // omission was ours. A url identifies; it does not describe.
  const subject = idx.name || idx.headline || idx.title;
  if (typeof subject === 'string' && subject) out.name = subject;

  const unresolved = [];
  let positional = null;

  for (const raw of fields.slice(0, MAX_FIELDS)) {
    const name = String(raw).trim();
    if (!name) continue;
    const key = name.toLowerCase();

    if (key.includes('[')) {
      if (positional === null) positional = positionalIndex(payload);
      if (key in positional) out[name] = positional[key];
      else unresolved.push(name);
      continue;
    }

    if (key in idx) {
      out[name] = idx[key];
      continue;
    }
    // Suffix match: "availability" resolves "offers.availability".
    const hit = Object.entries(idx).find(([p]) => p.endsWith(`.${key}`) || p === key);
    if (hit) out[name] = hit[1];
    else unresolved.push(name);
  }

  if (unresolved.length) {
    out['ubag:unresolved'] = unresolved;
    out['ubag:full_payload'] = '?ubag=full';
  }
  return out;
}

function parseFields(value) {
  return String(value || '')
    .split(',')
    .map((f) => f.trim())
    .filter(Boolean);
}

/**
 * Separate UBAG control parameters from the origin's own query string.
 *
 * Control parameters must not reach the origin: forwarding ?ubag.fields=
 * upstream is at best ignored and at worst poisons a cache key.
 */
function splitUbagQuery(query) {
  const params = new URLSearchParams(query || '');
  const control = {};
  const passthrough = new URLSearchParams();
  for (const [key, value] of params) {
    if (key === 'ubag' || key.startsWith('ubag.')) control[key] = value;
    else passthrough.append(key, value);
  }
  return { control, upstreamQuery: passthrough.toString() };
}

/**
 * Choose the representation. Returns { body, mode }.
 *
 * The no-parameter response is the unchanged full payload. Every addition is
 * opt-in, because changing the default would alter the response shape for
 * agents already built against the published format.
 */
function shapePayload(payload, control = {}) {
  if ('ubag.manifest' in control) return { body: manifest(payload), mode: 'manifest' };
  if ('ubag.fields' in control) {
    return { body: resolve(payload, parseFields(control['ubag.fields'])), mode: 'scoped' };
  }
  // Unrecognised values fall through rather than erroring. A caller sending a
  // mode we do not have should still get a usable page.
  return { body: payload, mode: 'full' };
}

module.exports = {
  indexFields,
  manifest,
  resolve,
  parseFields,
  splitUbagQuery,
  shapePayload,
};
