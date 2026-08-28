/**
 * `npx ubag-web init` writes into somebody else's repo, so the tests that
 * matter are the ones about what it refuses to do.
 *
 * Plus one that neither SDK can assert alone: the skill templates in this
 * package are copies of the canonical files in ubag-python, and copies drift.
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const { main, install, check, skillVersion, SKILLS, sdkVersion } =
  require('../src/init');

let root;
let log;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'ubag-init-'));
  log = [];
  jest.spyOn(console, 'log').mockImplementation((m) => log.push(String(m)));
});

afterEach(() => {
  console.log.mockRestore();
  fs.rmSync(root, { recursive: true, force: true });
});

const skillPath = (name) =>
  path.join(root, '.agents', 'skills', name, 'SKILL.md');
const output = () => log.join('\n');

// ---------------------------------------------------------------------------
// What it writes.
// ---------------------------------------------------------------------------

test('init writes the publisher skill by default', () => {
  expect(main(['init', '--dir', root])).toBe(0);
  expect(fs.existsSync(skillPath('ubag-publisher'))).toBe(true);
  expect(fs.existsSync(skillPath('ubag-agent'))).toBe(false);
});

test('--agent writes the other one', () => {
  main(['init', '--agent', '--dir', root]);
  expect(fs.existsSync(skillPath('ubag-agent'))).toBe(true);
  expect(fs.existsSync(skillPath('ubag-publisher'))).toBe(false);
});

test('--both writes both', () => {
  main(['init', '--both', '--dir', root]);
  for (const name of Object.values(SKILLS)) {
    expect(fs.existsSync(skillPath(name))).toBe(true);
  }
});

// ---------------------------------------------------------------------------
// Idempotence.
// ---------------------------------------------------------------------------

test('running it twice is a no-op', () => {
  install(root, ['publisher']);
  expect(install(root, ['publisher']).map((r) => r.outcome)).toEqual(['unchanged']);
});

test('a modified skill is restored and says so', () => {
  install(root, ['publisher']);
  fs.writeFileSync(skillPath('ubag-publisher'), 'edited by hand\n');
  expect(install(root, ['publisher']).map((r) => r.outcome)).toEqual(['updated']);
  expect(fs.readFileSync(skillPath('ubag-publisher'), 'utf8'))
    .not.toContain('edited by hand');
});

// ---------------------------------------------------------------------------
// What it refuses to touch.
// ---------------------------------------------------------------------------

test('an existing AGENTS.md is never modified', () => {
  const theirs = '# Our house rules\n\nDo not run migrations on Friday.\n';
  fs.writeFileSync(path.join(root, 'AGENTS.md'), theirs);

  main(['init', '--dir', root]);

  expect(fs.readFileSync(path.join(root, 'AGENTS.md'), 'utf8')).toBe(theirs);
  expect(output()).toContain('already exists and was not modified');
  // The refusal has to say what to add, or it is a dead end.
  expect(output()).toContain('.agents/skills/ubag-publisher/SKILL.md');
});

test('an existing CLAUDE.md is never modified', () => {
  const theirs = '@AGENTS.md\n<!-- plus our own notes -->\n';
  fs.writeFileSync(path.join(root, 'CLAUDE.md'), theirs);

  main(['init', '--dir', root]);

  expect(fs.readFileSync(path.join(root, 'CLAUDE.md'), 'utf8')).toBe(theirs);
  expect(output()).toContain('Confirm it reads AGENTS.md');
});

test('a fresh repo gets the pointer that was actually verified', () => {
  main(['init', '--dir', root]);
  expect(fs.readFileSync(path.join(root, 'CLAUDE.md'), 'utf8')).toBe('@AGENTS.md\n');
  expect(fs.existsSync(path.join(root, '.claude'))).toBe(false);
});

// ---------------------------------------------------------------------------
// Staleness.
// ---------------------------------------------------------------------------

test('a freshly written skill is not stale', () => {
  install(root, ['publisher', 'agent']);
  expect(check(root)).toEqual([]);
});

test('an old skill is reported stale', () => {
  install(root, ['publisher']);
  const target = skillPath('ubag-publisher');
  fs.writeFileSync(target, fs.readFileSync(target, 'utf8')
    .replace(`ubag_skill_version: ${sdkVersion()}`, 'ubag_skill_version: 0.1.0'));
  expect(check(root)).toEqual([{ name: 'ubag-publisher', found: '0.1.0' }]);
});

test('--check exits nonzero when stale', () => {
  install(root, ['agent']);
  fs.writeFileSync(skillPath('ubag-agent'), 'no frontmatter here\n');
  expect(main(['init', '--check', '--dir', root])).toBe(1);
});

test('absence is not staleness', () => {
  expect(check(root)).toEqual([]);
  expect(main(['init', '--check', '--dir', root])).toBe(0);
});

test('every shipped template carries this version stamp', () => {
  for (const { target } of install(root, ['publisher', 'agent'])) {
    expect(skillVersion(fs.readFileSync(target, 'utf8'))).toBe(sdkVersion());
  }
});

// ---------------------------------------------------------------------------
// The copies must not drift.
// ---------------------------------------------------------------------------

test('the templates match the canonical Python copies', () => {
  const canonical = path.resolve(
    __dirname, '..', '..', 'ubag-python', 'src', 'ubag', '_skills');

  // Skipped when installed from an npm tarball, where the sibling repo is not
  // present. In the monorepo, where drift actually happens, it runs.
  if (!fs.existsSync(canonical)) return;

  for (const kind of ['publisher', 'agent']) {
    expect(fs.readFileSync(path.join(__dirname, '..', 'src', 'skills', `${kind}.md`), 'utf8'))
      .toBe(fs.readFileSync(path.join(canonical, `${kind}.md`), 'utf8'));
  }
});
