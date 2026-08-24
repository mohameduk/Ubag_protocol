'use strict';

/**
 * Scoped retrieval, Node side.
 *
 * These mirror the Python tests deliberately. Two implementations of one wire
 * format drift unless something asserts they agree, and a client that resolves
 * a field the other cannot is worse than no client, because the disagreement
 * only surfaces at a customer.
 */

const {
  indexFields,
  manifest,
  resolve,
  parseFields,
  splitUbagQuery,
  shapePayload,
} = require('../src/scoped');

const PAYLOAD = {
  'ubag:source': 'https://madamefathia.com/p/3391',
  structured_data: [{
    '@context': 'https://schema.org',
    '@type': 'Product',
    name: 'Manteau 3391',
    sku: 'MF-M3391',
    material: 'Wool and silk jacquard',
    offers: {
      '@type': 'Offer',
      price: '689.00',
      priceCurrency: 'EUR',
      availability: 'https://schema.org/InStock',
    },
    aggregateRating: { '@type': 'AggregateRating', ratingValue: '4.8', reviewCount: 184 },
  }],
  meta: { title: 'Manteau 3391' },
};

const HOURS = {
  'ubag:source': 'https://madamefathia.com/',
  structured_data: [{
    '@type': 'Store',
    name: 'Maison Fathia',
    openingHoursSpecification: [
      { dayOfWeek: ['Monday', 'Friday'], opens: '09:30', closes: '18:30' },
      { dayOfWeek: 'Saturday', opens: '10:00', closes: '17:00' },
    ],
  }],
  meta: {},
};

// ---------------------------------------------------------------------------
// Query splitting
// ---------------------------------------------------------------------------

test('control params are extracted', () => {
  const { control, upstreamQuery } = splitUbagQuery('ubag.fields=price,sku');
  expect(control).toEqual({ 'ubag.fields': 'price,sku' });
  expect(upstreamQuery).toBe('');
});

test("the origin's own params survive and ours do not leak upstream", () => {
  const { control, upstreamQuery } = splitUbagQuery('color=blue&ubag.fields=sku&page=2');
  expect(control).toEqual({ 'ubag.fields': 'sku' });
  expect(upstreamQuery).not.toContain('ubag');
  expect(upstreamQuery).toContain('color=blue');
  expect(upstreamQuery).toContain('page=2');
});

// ---------------------------------------------------------------------------
// Representations
// ---------------------------------------------------------------------------

test('no parameter returns the payload untouched', () => {
  const { body, mode } = shapePayload(PAYLOAD, {});
  expect(mode).toBe('full');
  expect(body).toBe(PAYLOAD);
});

test('unknown ubag value falls back to the default', () => {
  expect(shapePayload(PAYLOAD, { ubag: 'nonsense' }).mode).toBe('full');
});

test('scoped returns only the requested fields', () => {
  const { body, mode } = shapePayload(PAYLOAD, {
    'ubag.fields': 'price,priceCurrency,availability',
  });
  expect(mode).toBe('scoped');
  expect(body.price).toBe('689.00');
  expect(body.priceCurrency).toBe('EUR');
  expect(body.availability).toBe('https://schema.org/InStock');
  expect(body.text_content).toBeUndefined();
});

test('nested paths resolve without the agent knowing the shape', () => {
  const body = resolve(PAYLOAD, ['ratingValue', 'reviewCount']);
  expect(body.ratingValue).toBe('4.8');
  expect(body.reviewCount).toBe(184);
});

test('misses are reported, not omitted', () => {
  const body = resolve(PAYLOAD, ['price', 'startDate']);
  expect(body.price).toBe('689.00');
  // Absence must be explicit: "says nothing about startDate" is not the same
  // as "startDate is empty", and an agent cannot act on the difference unless
  // we state it.
  expect(body['ubag:unresolved']).toEqual(['startDate']);
  expect(body['ubag:full_payload']).toBeDefined();
});

test('a page with no structured data resolves nothing and says so', () => {
  const bare = { 'ubag:source': 'https://x/bare', structured_data: [], meta: {} };
  const body = resolve(bare, ['price', 'availability']);
  expect(body['ubag:unresolved'].sort()).toEqual(['availability', 'price']);
  expect(body.price).toBeUndefined();
});

test('manifest lists fields without returning values', () => {
  const body = manifest(PAYLOAD);
  expect(body['ubag:fields']).toContain('price');
  expect(body['ubag:types']).toContain('Product');
  expect(JSON.stringify(body['ubag:fields'])).not.toContain('689.00');
});

// ---------------------------------------------------------------------------
// The subject anchor
// ---------------------------------------------------------------------------

test('a scoped answer always names its subject', () => {
  // A price with no subject is correct and unusable. Handed one, a model
  // answered NOT PRESENT rather than attribute it to the wrong product.
  const body = resolve(PAYLOAD, ['price']);
  expect(body.name).toBe('Manteau 3391');
  expect(body.price).toBe('689.00');
});

test('the anchor does not overwrite a requested field', () => {
  const body = resolve(PAYLOAD, ['name', 'price']);
  expect(body.name).toBe('Manteau 3391');
  expect(body['ubag:unresolved']).toBeUndefined();
});

// ---------------------------------------------------------------------------
// Positional access
// ---------------------------------------------------------------------------

test('a specific list element is reachable', () => {
  expect(resolve(HOURS, ['openingHoursSpecification[1].opens'])['openingHoursSpecification[1].opens'])
    .toBe('10:00');
  expect(resolve(HOURS, ['openingHoursSpecification[0].opens'])['openingHoursSpecification[0].opens'])
    .toBe('09:30');
});

test('unindexed access still collapses to the first element', () => {
  // The default must not change: offers.price, never offers[0].price.
  expect(resolve(HOURS, ['opens']).opens).toBe('09:30');
});

test('an out of range index is reported, not clamped', () => {
  expect(resolve(HOURS, ['openingHoursSpecification[9].opens'])['ubag:unresolved'])
    .toEqual(['openingHoursSpecification[9].opens']);
});

test('the index is relative to the block, not the page', () => {
  // A caller must not have to know how many ld+json script tags a page carries.
  const body = resolve(HOURS, ['[0].openingHoursSpecification[1].opens']);
  expect(body['ubag:unresolved']).toBeDefined();
});

// ---------------------------------------------------------------------------
// Cross-language parity
// ---------------------------------------------------------------------------

test('field paths and index keys match the Python implementation', () => {
  const idx = indexFields(PAYLOAD);
  // Lowercased dotted paths, plus the bare leaf name, exactly as scoped.py.
  //
  // Object.keys, not toHaveProperty: jest reads a dot in a property name as
  // nesting, so toHaveProperty('offers.price') looks for idx.offers.price and
  // fails on a key that is literally there.
  const keys = Object.keys(idx);
  for (const key of ['offers.price', 'price', 'aggregaterating.ratingvalue', 'ratingvalue']) {
    expect(keys).toContain(key);
  }
});

test('parseFields trims and drops empties', () => {
  expect(parseFields(' price , , sku ')).toEqual(['price', 'sku']);
  expect(parseFields('')).toEqual([]);
});

// ---------------------------------------------------------------------------
// Two bugs that shipped in v0.5.0
// ---------------------------------------------------------------------------

const ARTICLE = {
  'ubag:source': 'https://example.com/journal/gestes.html',
  structured_data: [{
    '@context': 'https://schema.org',
    '@type': 'NewsArticle',
    headline: 'Les gestes de la main',
    wordCount: '42160',
    author: { '@type': 'Person', name: 'Leila Ben Youssef' },
    publisher: { '@type': 'Organization', name: 'Maison Fathia' },
  }],
  meta: {},
};

const STORE = {
  'ubag:source': 'https://example.com/',
  structured_data: [{
    '@type': 'Store',
    name: 'Maison Fathia',
    openingHoursSpecification: [
      { '@type': 'OpeningHoursSpecification',
        dayOfWeek: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'],
        opens: '09:30', closes: '18:30' },
      { '@type': 'OpeningHoursSpecification', dayOfWeek: 'Saturday',
        opens: '10:00', closes: '17:00' },
    ],
  }],
  meta: {},
};

test('the anchor names the article, not its author', () => {
  // The index is flattened, so the bare key "name" was filled from author.name
  // and every article told agents its subject was a person. Handed
  // {"name":"Leila Ben Youssef","wordCount":"42160"} and asked for the edition
  // length, a model answered NOT PRESENT. Correctly: nothing in that payload
  // says what has 42,160 words.
  const body = resolve(ARTICLE, ['wordCount']);
  expect(body.name).toBe('Les gestes de la main');
  expect(body.wordCount).toBe('42160');
});

test('a nested publisher is not the subject either', () => {
  expect(resolve(ARTICLE, ['wordCount']).name).not.toBe('Maison Fathia');
});

test('a list of plain strings is reachable', () => {
  // Both walkers only recursed into objects, so a scalar array emitted nothing.
  // dayOfWeek was unreachable, and with it keywords, sameAs, all of them.
  expect(resolve(STORE, ['dayOfWeek']).dayOfWeek).toBe('Monday');
});

test('a specific element of a scalar list is reachable', () => {
  const body = resolve(STORE, ['openingHoursSpecification[0].dayOfWeek[4]']);
  expect(body['openingHoursSpecification[0].dayOfWeek[4]']).toBe('Friday');
});

// ---------------------------------------------------------------------------
// Containing-entity expansion, and lean
// ---------------------------------------------------------------------------

test('auto expands a price to the offer holding it', () => {
  const { body, mode } = shapePayload(PAYLOAD, {
    'ubag.fields': 'price', 'ubag.profile': 'auto',
  });
  expect(mode).toBe('auto');
  expect(body['offers.price']).toBe('689.00');
  expect(body['offers.pricecurrency']).toBe('EUR');
});

test('auto needs no vertical knowledge', () => {
  // Nothing here knows what a clinic is.
  const clinic = {
    'ubag:source': 'https://example.clinic/',
    structured_data: [{
      '@type': 'MedicalClinic',
      name: 'Hamilton Family Practice',
      address: { '@type': 'PostalAddress', streetAddress: '120 King St W',
        addressLocality: 'Hamilton', addressCountry: 'CA' },
    }],
    meta: {},
  };
  const { body } = shapePayload(clinic, {
    'ubag.fields': 'streetAddress', 'ubag.profile': 'auto',
  });
  expect(body['address.streetaddress']).toBe('120 King St W');
  expect(body['address.addresscountry']).toBe('CA');
});

test('auto does not open the root entity', () => {
  const { body } = shapePayload(PAYLOAD, {
    'ubag.fields': 'sku', 'ubag.profile': 'auto',
  });
  expect(body.sku).toBe('MF-M3391');
  expect(body.material).toBeUndefined();
});

test('lean drops the envelope and reads the enum aloud', () => {
  const { body, mode } = shapePayload(PAYLOAD, {
    'ubag.fields': 'availability', 'ubag': 'lean',
  });
  expect(mode).toBe('lean');
  expect(body.availability).toBe('in stock');
  expect(body['@context']).toBeUndefined();
  expect(body.url).toBeUndefined();
  expect(body.name).toBe('Manteau 3391');   // the anchor is not envelope
});

test('scoped keeps the canonical url so existing agents keep working', () => {
  const { body } = shapePayload(PAYLOAD, { 'ubag.fields': 'availability' });
  expect(body.availability).toBe('https://schema.org/InStock');
});
