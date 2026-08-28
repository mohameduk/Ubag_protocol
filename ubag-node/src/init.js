/**
 * `npx ubag-web init` writes agent instructions into the project that
 * installed us.
 *
 * A file shipped inside node_modules is never read. Coding agents look for
 * AGENTS.md, CLAUDE.md and .agents/skills at the *project root*. So the package
 * carries templates and this copies them out to where they will be found.
 *
 * Behaviour is deliberately identical to the Python `ubag init`, including
 * which files it refuses to touch. The two SDKs are one protocol and a
 * developer who has used one should not have to relearn the other.
 *
 * The skill templates under src/skills/ are copies of the canonical files in
 * ubag-python/src/ubag/_skills/. They have to be copies, because the two
 * packages publish separately and neither can reach into the other once
 * installed. tests/init.test.js asserts they are byte-identical whenever the
 * sibling repo is present, so the drift is caught here rather than by a user.
 */
'use strict';

const fs = require('fs');
const path = require('path');

const SKILLS = { publisher: 'ubag-publisher', agent: 'ubag-agent' };

const VERSION_LINE = /^ubag_skill_version:\s*(\S+)\s*$/m;

const AGENTS_MD = (lines) => `# Agent instructions

## UBAG

This project uses UBAG. The working instructions are in the skill files below.
Read the relevant one before touching UBAG configuration or writing code that
fetches a web page to extract a fact from it.

${lines}
`;

const CLAUDE_MD = '@AGENTS.md\n';

function sdkVersion() {
  return require('../package.json').version;
}

const PLACEHOLDER = '{{ubag_version}}';

/**
 * The shipped template for one audience, stamped with the SDK version.
 *
 * The stamp is substituted at write time rather than written into the template
 * as a literal. A literal was the first attempt and it is silently wrong: the
 * file ships stamped with whatever release it was authored under, check()
 * compares that stamp to the *installed* version, and every bump makes a
 * freshly written skill report itself stale on the spot.
 */
function template(kind, version) {
  const text = fs.readFileSync(
    path.join(__dirname, 'skills', `${kind}.md`), 'utf8');
  return text.split(PLACEHOLDER).join(version || sdkVersion());
}

function skillVersion(text) {
  const found = text.match(VERSION_LINE);
  return found ? found[1] : null;
}

/**
 * Write only when the content differs. Returns what happened.
 *
 * Idempotence is the contract: running init twice, or after an upgrade, must be
 * safe and must say which of the two it was.
 */
function write(target, text) {
  if (fs.existsSync(target)) {
    if (fs.readFileSync(target, 'utf8') === text) return 'unchanged';
    fs.writeFileSync(target, text);
    return 'updated';
  }
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, text);
  return 'written';
}

function install(root, kinds, version) {
  return kinds.map((kind) => {
    const target = path.join(root, '.agents', 'skills', SKILLS[kind], 'SKILL.md');
    return { kind, target, outcome: write(target, template(kind, version)) };
  });
}

/** Skills present in `root` whose stamp is not this SDK's version. */
function check(root, version) {
  const want = version || sdkVersion();
  const stale = [];
  for (const name of Object.values(SKILLS)) {
    const target = path.join(root, '.agents', 'skills', name, 'SKILL.md');
    if (!fs.existsSync(target)) continue;
    const found = skillVersion(fs.readFileSync(target, 'utf8'));
    if (found !== want) stale.push({ name, found });
  }
  return stale;
}

function main(argv = process.argv.slice(2)) {
  const args = new Set(argv);
  if (!args.has('init')) {
    console.log('usage: ubag-web init [--agent|--both] [--check] [--dir <path>]');
    return 1;
  }

  const dirAt = argv.indexOf('--dir');
  const root = path.resolve(dirAt === -1 ? '.' : argv[dirAt + 1]);

  if (args.has('--check')) {
    const stale = check(root);
    if (stale.length === 0) {
      console.log(`UBAG skills are current (${sdkVersion()}).`);
      return 0;
    }
    for (const { name, found } of stale) {
      console.log(`  ${name}: ${found || 'unstamped'}, SDK is ${sdkVersion()}`);
    }
    console.log('\nRun `npx ubag-web init` to refresh.');
    return 1;
  }

  const kinds = args.has('--both') ? ['publisher', 'agent']
              : args.has('--agent') ? ['agent']
              : ['publisher'];

  for (const { target, outcome } of install(root, kinds)) {
    console.log(`  ${outcome.padEnd(10)} ${path.relative(root, target)}`);
  }

  const lines = kinds
    .map((k) => `- \`.agents/skills/${SKILLS[k]}/SKILL.md\``)
    .join('\n');

  const agentsMd = path.join(root, 'AGENTS.md');
  if (fs.existsSync(agentsMd)) {
    console.log(`\nAGENTS.md already exists and was not modified. Add:\n\n${lines}`);
  } else {
    write(agentsMd, AGENTS_MD(lines));
    console.log('  written    AGENTS.md');
  }

  const claudeMd = path.join(root, 'CLAUDE.md');
  if (fs.existsSync(claudeMd)) {
    console.log('CLAUDE.md already exists and was not modified. '
              + 'Confirm it reads AGENTS.md (a line containing `@AGENTS.md`).');
  } else {
    write(claudeMd, CLAUDE_MD);
    console.log('  written    CLAUDE.md');
  }

  return 0;
}

module.exports = {
  main, install, check, skillVersion, template, SKILLS, sdkVersion, PLACEHOLDER,
};
