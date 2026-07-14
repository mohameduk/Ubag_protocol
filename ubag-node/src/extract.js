'use strict';

/**
 * Tier 1 structured-data extraction — mirrors ubag-python/src/ubag/_extract.py.
 *
 * Harvests what the site already declares: JSON-LD `<script type=application/
 * ld+json>`, OpenGraph `<meta property=og:*>`, and standard meta/title/canonical
 * tags. Everything here is owner-declared, so nothing is inferred or guessed.
 * Pure function: HTML string in, plain object out. No network, no dependencies.
 *
 * Cross-language parity: the JSON-LD nodes are pure JSON, so they parse to the
 * exact same objects as the Python SDK. OG/meta/title values are raw attribute
 * text and match for entity-free content (best-effort parity for text).
 */

function decodeEntities(s) {
  return String(s)
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#0*39;/g, "'")
    .replace(/&apos;/g, "'");
}

function parseAttrs(tagInner) {
  const attrs = {};
  const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'>]+))/g;
  let m;
  while ((m = re.exec(tagInner))) {
    const key = m[1].toLowerCase();
    const val = m[3] !== undefined ? m[3] : m[4] !== undefined ? m[4] : m[5] || '';
    attrs[key] = decodeEntities(val);
  }
  return attrs;
}

function iterJsonld(obj, out) {
  if (Array.isArray(obj)) {
    for (const it of obj) iterJsonld(it, out);
  } else if (obj && typeof obj === 'object') {
    if (Array.isArray(obj['@graph'])) {
      for (const it of obj['@graph']) iterJsonld(it, out);
    } else {
      out.push(obj);
    }
  }
}

function extractStructuredData(html) {
  html = String(html || '');
  const jsonld = [];
  const ldRe = /<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = ldRe.exec(html))) {
    const raw = m[1].trim();
    if (!raw) continue;
    try {
      iterJsonld(JSON.parse(raw), jsonld);
    } catch {
      /* skip malformed block, keep parsing */
    }
  }

  const og = {};
  const twitter = {};
  const meta = {};
  const metaRe = /<meta\b([^>]*?)\/?>/gi;
  while ((m = metaRe.exec(html))) {
    const a = parseAttrs(m[1]);
    if (a.content === undefined) continue;
    const prop = (a.property || '').trim().toLowerCase();
    const name = (a.name || '').trim().toLowerCase();
    if (prop.startsWith('og:')) {
      const k = prop.slice(3);
      if (!(k in og)) og[k] = a.content;
    } else if (name.startsWith('twitter:')) {
      const k = name.slice(8);
      if (!(k in twitter)) twitter[k] = a.content;
    } else if (name === 'description' || name === 'keywords' || name === 'author') {
      if (!(name in meta)) meta[name] = a.content;
    }
  }

  const titleM = /<title\b[^>]*>([\s\S]*?)<\/title>/i.exec(html);
  const title = (titleM ? decodeEntities(titleM[1]).trim() : '') || og.title || null;

  let canonical = null;
  const linkRe = /<link\b([^>]*?)\/?>/gi;
  while ((m = linkRe.exec(html))) {
    const a = parseAttrs(m[1]);
    if ((a.rel || '').toLowerCase().includes('canonical') && a.href && !canonical) {
      canonical = a.href.trim();
    }
  }

  let lang = null;
  const htmlTagM = /<html\b([^>]*?)>/i.exec(html);
  if (htmlTagM) {
    const a = parseAttrs(htmlTagM[1]);
    if (a.lang) lang = a.lang.trim();
  }

  return { jsonld, og, twitter, meta, title, canonical, lang };
}

const OG_TYPE_TO_SCHEMA = {
  website: 'WebSite',
  article: 'Article',
  product: 'Product',
  profile: 'ProfilePage',
  book: 'Book',
  'video.movie': 'Movie',
};

function ogTypeToSchema(t) {
  if (!t) return null;
  return OG_TYPE_TO_SCHEMA[String(t).trim().toLowerCase()] || null;
}

module.exports = { extractStructuredData, ogTypeToSchema };
