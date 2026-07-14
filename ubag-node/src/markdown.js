'use strict';

/**
 * HTML → Markdown for the honest-fallback content layer.
 * Mirrors ubag-python/src/ubag/_markdown.py.
 *
 * Serves readable page content as clearly-labeled UNSTRUCTURED Markdown instead
 * of guessing types for prose the owner never encoded. Boilerplate is stripped
 * first. Deterministic within this SDK; not promised byte-identical to Python
 * (HTML-to-text differs by parser), but semantically equivalent.
 */

const SKIP_TAGS = new Set([
  'head', 'title', 'script', 'style', 'noscript', 'template', 'svg', 'nav',
  'header', 'footer', 'aside', 'form', 'button', 'iframe',
]);
const HEADINGS = new Set(['h1', 'h2', 'h3', 'h4', 'h5', 'h6']);
const BLOCK = new Set(['p', 'div', 'section', 'article', 'main', 'table', 'tr']);

function decodeEntities(s) {
  return String(s)
    .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#0*39;/g, "'").replace(/&apos;/g, "'")
    .replace(/&nbsp;/g, ' ');
}

function hrefOf(attrs) {
  const m = /\bhref\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'>]+))/i.exec(attrs);
  if (!m) return null;
  return (m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4] || '').trim() || null;
}

function stripBoilerplate(html) {
  for (const tag of SKIP_TAGS) {
    html = html.replace(new RegExp(`<${tag}\\b[^>]*>[\\s\\S]*?<\\/${tag}>`, 'gi'), ' ');
  }
  return html;
}

function normalize(md, maxChars) {
  md = md
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .replace(/[ \t]{2,}/g, ' ')
    .trim();
  if (maxChars && md.length > maxChars) {
    md = md.slice(0, maxChars).replace(/\s+$/, '') + '\n\n… [truncated]';
  }
  return md;
}

function htmlToMarkdown(html, maxChars = null) {
  html = stripBoilerplate(String(html || ''));
  const parts = [];
  const st = { skip: 0, pre: 0, list: [], href: null };
  const tagRe = /<(\/?)([a-zA-Z0-9]+)((?:[^>"']|"[^"]*"|'[^']*')*)\/?>/g;
  let last = 0;
  let m;
  while ((m = tagRe.exec(html))) {
    if (m.index > last) handleText(parts, st, html.slice(last, m.index));
    last = tagRe.lastIndex;
    const tag = m[2].toLowerCase();
    if (m[1] === '/') handleEnd(parts, st, tag);
    else handleStart(parts, st, tag, m[3]);
  }
  if (last < html.length) handleText(parts, st, html.slice(last));
  return normalize(parts.join(''), maxChars);
}

function handleStart(parts, st, tag, attrs) {
  if (SKIP_TAGS.has(tag)) {
    st.skip += 1;
    return;
  }
  if (st.skip) return;
  if (HEADINGS.has(tag)) parts.push('\n\n' + '#'.repeat(parseInt(tag[1], 10)) + ' ');
  else if (BLOCK.has(tag)) parts.push('\n\n');
  else if (tag === 'br') parts.push('\n');
  else if (tag === 'hr') parts.push('\n\n---\n\n');
  else if (tag === 'ul' || tag === 'ol') {
    st.list.push([tag, 0]);
    parts.push('\n');
  } else if (tag === 'li') {
    const indent = '  '.repeat(Math.max(0, st.list.length - 1));
    const top = st.list[st.list.length - 1];
    if (top && top[0] === 'ol') {
      top[1] += 1;
      parts.push(`\n${indent}${top[1]}. `);
    } else parts.push(`\n${indent}- `);
  } else if (tag === 'strong' || tag === 'b') parts.push('**');
  else if (tag === 'em' || tag === 'i') parts.push('*');
  else if (tag === 'code' && !st.pre) parts.push('`');
  else if (tag === 'pre') {
    st.pre += 1;
    parts.push('\n\n```\n');
  } else if (tag === 'blockquote') parts.push('\n\n> ');
  else if (tag === 'a') {
    st.href = hrefOf(attrs);
    parts.push('[');
  }
}

function handleEnd(parts, st, tag) {
  if (SKIP_TAGS.has(tag)) {
    st.skip = Math.max(0, st.skip - 1);
    return;
  }
  if (st.skip) return;
  if (tag === 'strong' || tag === 'b') parts.push('**');
  else if (tag === 'em' || tag === 'i') parts.push('*');
  else if (tag === 'code' && !st.pre) parts.push('`');
  else if (tag === 'pre') {
    st.pre = Math.max(0, st.pre - 1);
    parts.push('\n```\n\n');
  } else if (tag === 'ul' || tag === 'ol') {
    st.list.pop();
    parts.push('\n');
  } else if (tag === 'a') {
    const href = st.href;
    st.href = null;
    parts.push(href ? `](${href})` : ']');
  } else if (HEADINGS.has(tag) || BLOCK.has(tag)) parts.push('\n');
}

function handleText(parts, st, text) {
  if (st.skip) return;
  if (st.pre) parts.push(decodeEntities(text));
  else parts.push(decodeEntities(text).replace(/\s+/g, ' '));
}

module.exports = { htmlToMarkdown };
