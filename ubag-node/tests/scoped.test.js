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
