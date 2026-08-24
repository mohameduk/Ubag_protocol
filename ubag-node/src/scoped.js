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
    for (const item of node) {
      // A list of plain strings used to yield nothing at all: the parent
      // yielded the list, which is not a leaf and was dropped, and this branch
      // only ever descended into objects. So dayOfWeek: ["Monday", ...] was
      // unreachable, and with it every scalar array. First element wins the
      // collapsed key, matching how offers.price behaves.
      if (isLeaf(item)) yield [prefix, item];
      else yield* walk(item, prefix);
    }
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
    for (let i = 0; i < node.length; i += 1) {
      const path = `${prefix}[${i}]`;
      // Same omission as walk: scalars inside a list were never emitted.
      if (isLeaf(node[i])) yield [path, node[i]];
      else yield* walkIndexed(node[i], path);
    }
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

const SUBJECT_KEYS = ['name', 'headline', 'title'];
// Entity types that are page furniture rather than what the page is about.
const NOT_SUBJECT = new Set(['breadcrumblist', 'listitem', 'website', 'searchaction',
  'webpage', 'imageobject', 'collectionpage', 'sitenavigationelement']);

/** Top-level entities, unwrapping @graph, never descending into values. */
function entities(payload) {
  const out = [];
  const stack = [...(payload.structured_data || [])];
  while (stack.length) {
    const node = stack.shift();
    if (Array.isArray(node)) { stack.unshift(...node); continue; }
    if (!node || typeof node !== 'object') continue;
    if (node['@graph'] !== undefined) {
      const g = node['@graph'];
      stack.unshift(...(Array.isArray(g) ? g : [g]));
      continue;
    }
    out.push(node);
  }
  return out;
}

/**
 * What this resource is about, from an entity's own top level.
 *
 * This used to read idx.name, and the index is flattened: every leaf is stored
 * under its bare name as well as its dotted path. A NewsArticle keeps its title
 * in headline and has no top-level name, so the bare "name" key was filled from
 * author.name and the anchor announced the subject of every article as a person.
 *
 * An agent then received {"name":"Leila Ben Youssef","wordCount":"42160"},
 * which describes a human being with a word count, and a model asked for the
 * edition length answered NOT PRESENT. Correctly: nothing in that payload says
 * what has 42,160 words. The anchor exists to prevent that misattribution and
 * was causing it.
 */
function subjectOf(payload) {
  const all = entities(payload);
  const pick = (skipFurniture) => {
    for (const ent of all) {
      const declared = ent['@type'] || '';
      const names = new Set((Array.isArray(declared) ? declared : [declared])
        .filter((t) => typeof t === 'string').map((t) => t.toLowerCase()));
      if (skipFurniture && [...names].some((n) => NOT_SUBJECT.has(n))) continue;
      for (const key of SUBJECT_KEYS) {
        const v = ent[key];
        if (typeof v === 'string' && v.trim()) return v.trim();
      }
    }
    return null;
  };
  const found = pick(true) || pick(false);
  if (found) return found;
  const title = (payload.meta || {}).title;
  return (typeof title === 'string' && title.trim()) ? title.trim() : null;
}

const SCHEMA_PREFIX = 'https://schema.org/';
const ENUM_WORDS = {
  instock: 'in stock', outofstock: 'out of stock', preorder: 'pre-order',
  presale: 'pre-sale', soldout: 'sold out', backorder: 'back-order',
  limitedavailability: 'limited availability', discontinued: 'discontinued',
  instoreonly: 'in store only', onlineonly: 'online only', onsale: 'on sale',
};

/**
 * "in stock", not https://schema.org/InStock.
 *
 * Consumers relay the canonical term verbatim: a model handed
 * https://schema.org/LimitedAvailability answers "LimitedAvailability", which
 * is not a sentence. Only values that arrived as a schema.org URL are touched,
 * because that prefix is what proves the string is an enum rather than ordinary
 * content; a product genuinely named "InStock" survives untouched.
 */
function leanValue(v) {
  if (typeof v !== 'string' || !v.startsWith(SCHEMA_PREFIX)) return v;
  const term = v.slice(SCHEMA_PREFIX.length);
  if (!term) return v;
  return ENUM_WORDS[term.toLowerCase()]
    || term.replace(/([a-z0-9])(?=[A-Z])/g, '$1 ').toLowerCase();
}

/** (requested-name -> full dotted path, every full path). */
function pathsOf(payload) {
  const where = {};
  const every = new Set();
  for (const source of [payload.structured_data || [], payload.meta || {}]) {
    for (const [path, value] of walk(source)) {
      if (!keep(value)) continue;
      const low = path.toLowerCase();
      every.add(low);
      if (!(low in where)) where[low] = low;
      const leaf = low.split('.').pop();
      if (!(leaf in where)) where[leaf] = low;
    }
  }
  return { where, every };
}

/**
 * Ask for a leaf, receive the sub-entity holding it.
 *
 * A price with no currency is not a cheap answer, it is one you cannot transact
 * on. Rather than a table of per-vertical intents, which is a catalogue nobody
 * finishes, this uses the grouping schema.org already did: properties that must
 * be read together are properties of the same entity. So a clinic's address
 * expands identically to a shop's, and nothing here knows what a clinic is.
 *
 * The root entity is never expanded; that is the full payload with extra steps.
 */
function autoExpand(payload, fields) {
  const { where, every } = pathsOf(payload);
  const out = [];
  for (const raw of fields) {
    const name = String(raw).trim();
    const key = name.toLowerCase().split('[')[0];
    const full = where[key]
      || Object.entries(where).find(([k]) => k.endsWith(`.${key}`))?.[1];
    if (!full || !full.includes('.')) { out.push(name); continue; }
    const owner = full.slice(0, full.lastIndexOf('.'));
    const siblings = [...every]
      .filter((p) => p.startsWith(`${owner}.`)
        && !p.slice(owner.length + 1).includes('.')
        // @type is plumbing: "offers.@type": "Offer" answers nothing an agent
        // could not read off the field names.
        && !p.endsWith('.@type'))
      .sort();
    out.push(...(siblings.length ? siblings : [name]));
  }
  const seen = new Set();
  return out.filter((f) => !seen.has(f.toLowerCase()) && seen.add(f.toLowerCase()));
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
function resolve(payload, fields, lean = false) {
  const idx = indexFields(payload);
  const out = lean ? {} : {
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
  const subject = subjectOf(payload);
  if (subject) out.name = subject;

  const unresolved = [];
  let positional = null;

  for (const raw of fields.slice(0, MAX_FIELDS)) {
    const name = String(raw).trim();
    if (!name) continue;
    const key = name.toLowerCase();

    if (key.includes('[')) {
      if (positional === null) positional = positionalIndex(payload);
      if (key in positional) out[name] = lean ? leanValue(positional[key]) : positional[key];
      else unresolved.push(name);
      continue;
    }

    if (key in idx) {
      out[name] = lean ? leanValue(idx[key]) : idx[key];
      continue;
    }
    // Suffix match: "availability" resolves "offers.availability".
    const hit = Object.entries(idx).find(([p]) => p.endsWith(`.${key}`) || p === key);
    if (hit) out[name] = lean ? leanValue(hit[1]) : hit[1];
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
  const lean = control.ubag === 'lean';

  if ('ubag.manifest' in control) return { body: manifest(payload), mode: 'manifest' };

  if (String(control['ubag.profile'] || '').trim().toLowerCase() === 'auto') {
    // ?ubag.fields=price&ubag.profile=auto
    //
    // Expand each requested leaf to the sub-entity holding it, so a price
    // cannot arrive without its currency. Derived from the publisher's own
    // structure rather than a table of intents, which is why it works on a
    // vertical nobody anticipated.
    const asked = parseFields(control['ubag.fields'] || '');
    if (asked.length) {
      return {
        body: resolve(payload, autoExpand(payload, asked), lean),
        mode: lean ? 'auto-lean' : 'auto',
      };
    }
  }

  if ('ubag.fields' in control) {
    return {
      body: resolve(payload, parseFields(control['ubag.fields']), lean),
      mode: lean ? 'lean' : 'scoped',
    };
  }
  // Unrecognised values fall through rather than erroring. A caller sending a
  // mode we do not have should still get a usable page.
  return { body: payload, mode: 'full' };
}

module.exports = {
  indexFields,
  manifest,
  resolve,
  subjectOf,
  autoExpand,
  parseFields,
  splitUbagQuery,
  shapePayload,
};
