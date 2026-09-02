/**
 * answer(), the named profiles, and the parity that was quietly missing.
 *
 * Both READMEs promise an identical, cross-verifiable wire format. They were
 * not identical: Python shipped five named profiles and Node handled only
 * `auto`, so a Python origin answered ?ubag.profile=hours and a Node origin
 * fell through and returned the whole page. Same request, two protocols.
 *
 * The fixtures below are byte-identical to the ones in
 * ubag-python/tests/test_answer_and_profiles.py on purpose. Two SDKs claiming
 * one wire format should be checkable by reading the two test files side by
 * side.
 */
'use strict';

const { Agent } = require('../src/client');
const { PROFILES, manifest, shapePayload, autoExpand } = require('../src/scoped');

const PRODUCT = {
  'ubag:source': 'https://shop.example.com/p/3391',
  structured_data: [{
    '@type': 'Product',
    name: 'Manteau laine',
    offers: {
      '@type': 'Offer', price: '862.00', priceCurrency: 'EUR',
      availability: 'https://schema.org/InStock',
    },
  }],
};

const CLINIC = {
  'ubag:source': 'https://clinic.example.com/',
  structured_data: [{
    '@type': 'MedicalClinic',
    name: 'Clinique Nord',
    telephone: '+33 1 23 45 67 89',
    address: {
      '@type': 'PostalAddress', streetAddress: '12 rue Ney',
      addressLocality: 'Lyon', addressCountry: 'FR',
    },
    openingHoursSpecification: [
      { '@type': 'OpeningHoursSpecification', dayOfWeek: 'Monday', opens: '09:00', closes: '18:00' },
      { '@type': 'OpeningHoursSpecification', dayOfWeek: 'Saturday', opens: '10:00', closes: '13:00' },
    ],
  }],
};

/** Captures the query instead of making a request. */
function recorder() {
  const a = Object.create(Agent.prototype);
  a.query = null;
  a._get = async (url, params) => { a.query = params; return { ok: true }; };
  return a;
}

const answered = (body) => Object.keys(body)
  .filter((k) => !k.startsWith('@') && !k.startsWith('ubag:') && k !== 'url' && k !== 'name');

// ---------------------------------------------------------------------------
// answer()
// ---------------------------------------------------------------------------

test('answer asks for expansion and lean without being told', async () => {
  const a = recorder();
  await a.answer('https://shop.example.com/p/3391', 'price');
  expect(a.query).toBe('ubag.fields=price&ubag.profile=auto&ubag=lean');
});

test('answer takes several fields', async () => {
  const a = recorder();
  await a.answer('https://x.example/p', 'price', 'availability');
  expect(a.query.startsWith('ubag.fields=price,availability&')).toBe(true);
});

test('fields pins lean so the origin version cannot change the shape', async () => {
  // S-UX/2.0 makes lean the default, but an origin still on 1.1 would answer
  // the same call with an envelope. Sent explicitly so a caller's result does
  // not depend on software they do not control.
  const a = recorder();
  await a.fields('https://x.example/p', ['offers.price']);
  expect(a.query).toBe('ubag.fields=offers.price&ubag=lean');
});

test('what answer actually returns', () => {
  const { body, mode } = shapePayload(PRODUCT,
    { 'ubag.fields': 'price', 'ubag.profile': 'auto', ubag: 'lean' });
  expect(mode).toBe('auto');
  expect(body['offers.price']).toBe('862.00');
  expect(body['offers.priceCurrency']).toBe('EUR');
  // Publisher casing. It used to lowercase to offers.pricecurrency, which is
  // not a name that appears anywhere on their page.
  expect(body['offers.pricecurrency']).toBeUndefined();
  expect(body['offers.availability']).toBe('in stock');
  expect(body.name).toBe('Manteau laine');
  expect(body['@context']).toBeUndefined();
});

test('unresolved survives lean', () => {
  const { body } = shapePayload(PRODUCT,
    { 'ubag.fields': 'calories', 'ubag.profile': 'auto', ubag: 'lean' });
  expect(body['ubag:unresolved']).toEqual(['calories']);
});

// ---------------------------------------------------------------------------
// Named profiles, which this SDK did not have.
// ---------------------------------------------------------------------------

test('a named profile is served rather than falling through to the full page', () => {
  const { body, mode } = shapePayload(CLINIC, { 'ubag.profile': 'hours' });
  expect(mode).toBe('profile');
  // Not the whole page. Before the port this returned CLINIC unchanged.
  expect(body.structured_data).toBeUndefined();
  expect(answered(body).length).toBeGreaterThan(0);
});

test('hours keeps the publisher casing and every entry', () => {
  const { body } = shapePayload(CLINIC, { 'ubag.profile': 'hours' });
  const keys = answered(body);
  // Saturday is the second entry, and an index that collapses lists would have
  // lost it. "When do you open on Saturday" is the question this exists for.
  expect(keys.some((k) => k.startsWith('openingHoursSpecification[1]'))).toBe(true);
  expect(keys.some((k) => k.includes('openinghours'))).toBe(false);
  // @type is plumbing and is dropped.
  expect(keys.some((k) => k.endsWith('.@type'))).toBe(false);
});

test('an unrecognised profile name does not claim the mode', () => {
  // Reporting "profile" for a request no profile served would make a typo
  // indistinguishable from a page with no data.
  const { mode } = shapePayload(CLINIC, { 'ubag.profile': 'nonsense' });
  expect(mode).not.toBe('profile');
});

test('a profile can be combined with explicit fields', () => {
  const { body } = shapePayload(CLINIC,
    { 'ubag.profile': 'contact', 'ubag.fields': 'name' });
  expect(body.telephone).toBe('+33 1 23 45 67 89');
});

// ---------------------------------------------------------------------------
// The manifest advertises what this resource can answer.
// ---------------------------------------------------------------------------

test('a product advertises price and not opening hours', () => {
  expect(manifest(PRODUCT)['ubag:profiles']).toEqual(['price']);
});

test('a clinic advertises the intents it can serve', () => {
  const found = manifest(CLINIC)['ubag:profiles'];
  expect(found).toEqual(expect.arrayContaining(['address', 'contact', 'hours']));
  expect(found).not.toContain('price');
});

test('a page with nothing advertises nothing', () => {
  expect(manifest({ structured_data: [] })['ubag:profiles']).toEqual([]);
});

test.each(Object.keys(PROFILES).sort())('an advertised profile answers something: %s', (name) => {
  for (const payload of [PRODUCT, CLINIC]) {
    if (!manifest(payload)['ubag:profiles'].includes(name)) continue;
    const { body, mode } = shapePayload(payload, { 'ubag.profile': name });
    expect(mode).toBe('profile');
    expect(answered(body).length).toBeGreaterThan(0);
  }
});

test.each(Object.keys(PROFILES).sort())('an unadvertised profile answers nothing: %s', (name) => {
  for (const payload of [PRODUCT, CLINIC]) {
    if (manifest(payload)['ubag:profiles'].includes(name)) continue;
    const { body } = shapePayload(payload, { 'ubag.profile': name });
    expect(answered(body)).toEqual([]);
  }
});

// ---------------------------------------------------------------------------
// Parity. The promise on both package pages.
// ---------------------------------------------------------------------------

test('the profile vocabulary matches the Python SDK', () => {
  expect(Object.keys(PROFILES).sort())
    .toEqual(['address', 'contact', 'hours', 'price', 'rating']);
});

test('autoExpand produces the same field list as Python', () => {
  // Verified against ubag-python: ['offers.availability', 'offers.price',
  // 'offers.priceCurrency']. Sorted on the lowercase path, emitted in the
  // publisher's casing, so the two SDKs agree byte for byte.
  expect(autoExpand(PRODUCT, ['price']))
    .toEqual(['offers.availability', 'offers.price', 'offers.priceCurrency']);
});
