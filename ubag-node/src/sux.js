'use strict';

/**
 * Branch B — Structured UX (S-UX) response builder.
 * Mirrors ubag-python/src/ubag/_sux.py.
 *
 * Confidence model (Tier 1): everything served is owner-declared (parsed
 * JSON-LD, OpenGraph, meta). Nothing is inferred. `ubag:provenance` records
 * where each part came from. site_meta always wins, acting as both an override
 * and an escape hatch for data the page does not expose.
 */
const { extractStructuredData, ogTypeToSchema } = require('./extract');

function buildJsonldResponse(host, path, siteMeta, claims, html = null) {
  const now = Math.floor(Date.now() / 1000);
  siteMeta = siteMeta || {};
  const sources = [];

  const base = {
    '@context': 'https://schema.org',
    '@type': 'WebSite',
    url: `https://${host}${path}`,
    name: host,
  };

  let declaredNodes = [];

  // ── Auto-harvest declared data (Tier 1) ────────────────────────────────────
  if (html) {
    const data = extractStructuredData(html);
    const og = data.og;

    if (Object.keys(og).length) sources.push('opengraph');
    else if (Object.keys(data.meta).length || data.title) sources.push('meta');

    const schemaType = ogTypeToSchema(og.type);
    if (schemaType) base['@type'] = schemaType;
    if (data.title) base.name = data.title;
    const desc = og.description || data.meta.description;
    if (desc) base.description = desc;
    if (og.image) base.image = og.image;
    if (data.canonical) base.url = data.canonical;
    if (data.lang) base.inLanguage = data.lang;

    declaredNodes = data.jsonld;
    if (declaredNodes.length) {
      sources.push('json-ld');
      const primary = declaredNodes[0];
      for (const key of ['@type', 'name', 'description', 'url', 'image']) {
        const v = primary[key];
        if (v !== undefined && (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean')) {
          base[key] = v;
        }
      }
    }
  }

  // ── Owner overrides always win ─────────────────────────────────────────────
  const siteFields = [];
  for (const [key, value] of Object.entries(siteMeta)) {
    if (key === 'type') base['@type'] = value;
    else {
      base[key] = value;
      siteFields.push(key);
    }
  }
  if (Object.keys(siteMeta).length) sources.push('site_meta');

  // ── UBAG envelope + provenance ─────────────────────────────────────────────
  base['ubag:source'] = `https://${host}`;
  base['ubag:served_at'] = now;
  base['ubag:agent'] = claims && claims.sub ? claims.sub : 'unknown';
  base['ubag:branch'] = 'B-AGENT';
  if (declaredNodes.length) base['ubag:declared'] = declaredNodes;
  base['ubag:provenance'] = {
    confidence: 'declared', // Tier 1 is all owner-declared; nothing inferred
    sources: [...new Set(sources)].sort(),
    fields_from_site_meta: siteFields.slice().sort(),
  };

  return base;
}

module.exports = { buildJsonldResponse };
