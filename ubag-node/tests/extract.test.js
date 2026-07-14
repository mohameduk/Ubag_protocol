'use strict';

const fs = require('fs');
const path = require('path');
const { extractStructuredData, ogTypeToSchema } = require('../src/extract');
const { htmlToMarkdown } = require('../src/markdown');
const { buildJsonldResponse } = require('../src/sux');
const { TTLCache } = require('../src/cache');
const { originHtml } = require('../src/middleware/express');

const FIXTURES = path.resolve(__dirname, '..', '..', 'tests', 'fixtures');
const GOLDEN = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'expected_jsonld.json'), 'utf8'));

// ── pure extraction ────────────────────────────────────────────────────────

test('extracts JSON-LD verbatim', () => {
  const html = fs.readFileSync(path.join(FIXTURES, 'product.html'), 'utf8');
  const d = extractStructuredData(html);
  expect(d.jsonld).toHaveLength(1);
  expect(d.jsonld[0]['@type']).toBe('Product');
  expect(d.jsonld[0].offers.price).toBe('19.99'); // preserved, not flattened
  expect(d.canonical).toBe('https://acme.com/widgets/blue');
  expect(d.lang).toBe('en');
  expect(d.og.type).toBe('product');
});

test('flattens @graph to nodes', () => {
  const html = fs.readFileSync(path.join(FIXTURES, 'graph.html'), 'utf8');
  const types = extractStructuredData(html).jsonld.map((n) => n['@type']).sort();
  expect(types).toEqual(['Organization', 'WebSite']);
});

test('malformed JSON-LD is skipped, not thrown', () => {
  const html = '<html><head><script type="application/ld+json">{bad,,}</script>' +
    '<title>Still Works</title></head><body></body></html>';
  const d = extractStructuredData(html);
  expect(d.jsonld).toEqual([]);
  expect(d.title).toBe('Still Works');
});

test('ogTypeToSchema only maps known types', () => {
  expect(ogTypeToSchema('product')).toBe('Product');
  expect(ogTypeToSchema('something-weird')).toBeNull();
});

// ── cross-language parity against the shared golden ────────────────────────

for (const name of Object.keys(GOLDEN).sort()) {
  test(`JSON-LD matches golden: ${name}`, () => {
    const html = fs.readFileSync(path.join(FIXTURES, name), 'utf8');
    expect(extractStructuredData(html).jsonld).toEqual(GOLDEN[name]);
  });
}

// ── envelope assembly + provenance ─────────────────────────────────────────

test('envelope passes JSON-LD through and marks declared', () => {
  const html = fs.readFileSync(path.join(FIXTURES, 'product.html'), 'utf8');
  const p = buildJsonldResponse('acme.com', '/widgets/blue', {}, { sub: 'ubag:a1' }, html);
  expect(p['@type']).toBe('Product');
  expect(p.url).toBe('https://acme.com/widgets/blue'); // from canonical
  expect(p.inLanguage).toBe('en');
  expect(p['ubag:declared'][0]['@type']).toBe('Product');
  expect(p['ubag:provenance'].confidence).toBe('declared');
  expect(p['ubag:provenance'].sources).toContain('json-ld');
});

test('site_meta overrides extracted data', () => {
  const html = fs.readFileSync(path.join(FIXTURES, 'product.html'), 'utf8');
  const p = buildJsonldResponse('acme.com', '/widgets/blue', { name: 'Owner', type: 'Store' }, {}, html);
  expect(p.name).toBe('Owner');
  expect(p['@type']).toBe('Store');
  expect(p['ubag:provenance'].fields_from_site_meta).toEqual(['name']);
});

test('backward compatible without html', () => {
  const p = buildJsonldResponse('acme.com', '/', { name: 'Acme', type: 'Store' }, { sub: 'ubag:a1' });
  expect(p['@type']).toBe('Store');
  expect(p.name).toBe('Acme');
  expect(p['ubag:declared']).toBeUndefined();
  expect(p['ubag:content']).toBeUndefined();
});

// ── Markdown content layer ─────────────────────────────────────────────────

const PROSE = `<html><head><title>Guide</title><script>x=1</script></head>
<body><nav><a href="/">home</a></nav><main>
<h1>Widget Guide</h1>
<p>The <strong>blue</strong> widget is <em>great</em>. See <a href="/buy">buy</a>.</p>
<ul><li>Durable</li><li>Light</li></ul>
</main><footer>nav junk</footer></body></html>`;

test('markdown strips boilerplate and formats', () => {
  const md = htmlToMarkdown(PROSE);
  expect(md).toContain('# Widget Guide');
  expect(md).toContain('**blue**');
  expect(md).toContain('*great*');
  expect(md).toContain('[buy](/buy)');
  expect(md).toContain('- Durable');
  expect(md).not.toContain('nav junk');
  expect(md).not.toContain('x=1');
});

test('markdown truncates to maxChars', () => {
  const md = htmlToMarkdown('<body><p>' + 'word '.repeat(500) + '</p></body>', 100);
  expect(md.length).toBeLessThanOrEqual(130);
  expect(md.endsWith('[truncated]')).toBe(true);
});

test('content layer labeled and marks confidence', () => {
  const p = buildJsonldResponse('acme.com', '/guide', {}, { sub: 'ubag:a1' }, PROSE, { includeMarkdown: true });
  expect(p['ubag:content'].format).toBe('markdown');
  expect(p['ubag:content'].source).toBe('extracted');
  expect(p['ubag:content'].text).toContain('# Widget Guide');
  expect(p['ubag:provenance'].sources).toContain('content-markdown');
  expect(['mixed', 'extracted']).toContain(p['ubag:provenance'].confidence);
});

test('content layer off by default in builder', () => {
  const p = buildJsonldResponse('acme.com', '/guide', {}, {}, PROSE);
  expect(p['ubag:content']).toBeUndefined();
  expect(p['ubag:provenance'].confidence).toBe('declared');
});

// ── TTLCache + origin fetch glue ───────────────────────────────────────────

test('TTLCache evicts LRU over size', () => {
  const c = new TTLCache(2, 100);
  c.set('a', 1);
  c.set('b', 2);
  c.get('a'); // touch a → b is LRU
  c.set('c', 3); // evicts b
  expect(c.get('b')).toBeUndefined();
  expect(c.get('a')).toBe(1);
});

test('originHtml caches and honors autoExtract + content-type', async () => {
  const html = '<html><head><title>X</title></head><body></body></html>';
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return { status: 200, headers: { get: () => 'text/html' }, text: async () => html };
  };
  const cache = new TTLCache(8, 100);
  const a = await originHtml('https://acme.com', '/p', { autoExtract: true, cache, fetchImpl });
  const b = await originHtml('https://acme.com', '/p', { autoExtract: true, cache, fetchImpl });
  expect(a).toContain('<title>X</title>');
  expect(b).toBe(a);
  expect(calls).toBe(1); // second served from cache

  // non-HTML response is ignored
  const jsonCache = new TTLCache(8, 100);
  const jsonFetch = async () => ({ status: 200, headers: { get: () => 'application/json' }, text: async () => '{}' });
  expect(await originHtml('https://acme.com', '/api', { autoExtract: true, cache: jsonCache, fetchImpl: jsonFetch })).toBeNull();

  // disabled → no fetch, returns null
  const off = await originHtml('https://acme.com', '/p2', { autoExtract: false, cache, fetchImpl });
  expect(off).toBeNull();
  expect(calls).toBe(1);
});
