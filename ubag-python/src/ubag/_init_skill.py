"""
`ubag init` writes agent instructions into the project that installed us.

A file shipped inside the package is never read. Coding agents look for
AGENTS.md, CLAUDE.md and .agents/skills at the *project root*, not inside
site-packages or node_modules. So the SDK carries templates and this command
copies them out into the consuming repo, where they will actually be found.

Two audiences, and they need opposite things:

    publisher   mounting the middleware in front of a site
    agent       building something that reads UBAG-enabled sites

What gets written, and why only these three paths:

    .agents/skills/<name>/SKILL.md   the real file, open skill standard
    AGENTS.md                        created only if absent, points at the skill
    CLAUDE.md                        created only if absent, contains @AGENTS.md

The CLAUDE.md line is the verified mechanism: a one-line `@AGENTS.md` pulls the
whole file into Claude Code's context, which is what keeps one repo from needing
two divergent instruction files. A pointer under .claude/skills is deliberately
NOT written, because that path's import semantics were not confirmed and a
pointer that silently resolves to nothing is worse than no pointer.

An existing AGENTS.md is never modified. It is somebody's file, it may be long,
and appending to it unasked is how a tool loses trust. The line to add is
printed instead.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from ubag import __version__

SKILLS = {
    "publisher": "ubag-publisher",
    "agent": "ubag-agent",
}

_VERSION_LINE = re.compile(r"^ubag_skill_version:\s*(\S+)\s*$", re.MULTILINE)

_AGENTS_MD = """# Agent instructions

## UBAG

This project uses UBAG. The working instructions are in the skill files below.
Read the relevant one before touching UBAG configuration or writing code that
fetches a web page to extract a fact from it.

{lines}
"""

_CLAUDE_MD = "@AGENTS.md\n"


PLACEHOLDER = "{{ubag_version}}"


def _template(kind: str, version: str | None = None) -> str:
    """
    The shipped template for one audience, stamped with the SDK version.

    The stamp is substituted at write time rather than written into the template
    as a literal. A literal was the first attempt and it is silently wrong: the
    file ships stamped with whatever release it was authored under, check()
    compares that stamp to the *installed* version, and every bump makes a
    freshly written skill report itself stale on the spot. Nobody would have
    seen it until the next release, and then everyone would.
    """
    path = Path(__file__).parent / "_skills" / f"{kind}.md"
    text = path.read_text(encoding="utf-8")
    return text.replace(PLACEHOLDER, version or __version__)


def skill_version(text: str) -> str | None:
    """The version stamped into a skill file, or None if it carries no stamp."""
    found = _VERSION_LINE.search(text)
    return found.group(1) if found else None


def _write(path: Path, text: str) -> str:
    """
    Write only when the content differs. Returns what happened.

    Idempotence is the whole contract here: running init twice, or running it
    after an SDK upgrade, must be safe and must say plainly which of the two
    happened.
    """
    if path.exists():
        current = path.read_text(encoding="utf-8")
        if current == text:
            return "unchanged"
        path.write_text(text, encoding="utf-8")
        return "updated"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return "written"


def install(root: Path, kinds: list[str],
            version: str | None = None) -> list[tuple[str, Path, str]]:
    """Copy the templates into `root`. Returns (kind, path, outcome) per file."""
    done: list[tuple[str, Path, str]] = []
    for kind in kinds:
        name = SKILLS[kind]
        target = root / ".agents" / "skills" / name / "SKILL.md"
        done.append((kind, target, _write(target, _template(kind, version))))
    return done


def check(root: Path, version: str | None = None) -> list[tuple[str, str | None]]:
    """
    Compare each installed skill against this SDK's version.

    A skill copied into a repo goes stale the moment the SDK ships again, and
    nobody re-runs init unprompted. Returns (name, installed_version) for every
    skill found whose stamp is not this version.
    """
    want = version or __version__
    stale: list[tuple[str, str | None]] = []
    for name in SKILLS.values():
        path = root / ".agents" / "skills" / name / "SKILL.md"
        if not path.exists():
            continue
        found = skill_version(path.read_text(encoding="utf-8"))
        if found != want:
            stale.append((name, found))
    return stale


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ubag",
        description="UBAG command line. Writes agent instructions into a project.")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser(
        "init", help="write UBAG agent instructions into this project")
    init.add_argument("--agent", action="store_true",
                      help="instructions for building an agent that reads sites")
    init.add_argument("--both", action="store_true",
                      help="write both the publisher and agent skills")
    init.add_argument("--dir", default=".", help="project root (default: cwd)")
    init.add_argument("--check", action="store_true",
                      help="report stale skills instead of writing anything")

    args = parser.parse_args(argv)
    root = Path(args.dir).resolve()

    if args.check:
        stale = check(root)
        if not stale:
            print(f"UBAG skills are current ({__version__}).")
            return 0
        for name, found in stale:
            print(f"  {name}: {found or 'unstamped'}, SDK is {__version__}")
        print("\nRun `ubag init` to refresh.")
        return 1

    if args.both:
        kinds = ["publisher", "agent"]
    elif args.agent:
        kinds = ["agent"]
    else:
        kinds = ["publisher"]

    results = install(root, kinds)
    for _, path, outcome in results:
        print(f"  {outcome:<10} {path.relative_to(root).as_posix()}")

    lines = "\n".join(
        f"- `.agents/skills/{SKILLS[k]}/SKILL.md`" for k in kinds)

    agents_md = root / "AGENTS.md"
    if agents_md.exists():
        print(f"\nAGENTS.md already exists and was not modified. Add:\n\n{lines}")
    else:
        _write(agents_md, _AGENTS_MD.format(lines=lines))
        print(f"  written    AGENTS.md")

    claude_md = root / "CLAUDE.md"
    if claude_md.exists():
        print("CLAUDE.md already exists and was not modified. "
              "Confirm it reads AGENTS.md (a line containing `@AGENTS.md`).")
    else:
        _write(claude_md, _CLAUDE_MD)
        print(f"  written    CLAUDE.md")

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
