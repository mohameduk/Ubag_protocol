"""
`ubag init` writes into somebody else's repo, so the tests that matter are the
ones about what it refuses to do.

Two properties are load-bearing:

  1. Running it twice changes nothing the second time. A tool that rewrites
     files on every invocation makes `git status` useless and teaches people to
     stop reading its output.

  2. An existing AGENTS.md is never touched. It is somebody's file, probably
     long, possibly the most important file in their repo. Appending to it
     unasked is how a tool gets uninstalled.
"""
from __future__ import annotations

import pytest

from ubag import __version__
from ubag._init_skill import SKILLS, check, install, main, skill_version


def skill_path(root, name):
    return root / ".agents" / "skills" / name / "SKILL.md"


# ---------------------------------------------------------------------------
# What it writes.
# ---------------------------------------------------------------------------

def test_init_writes_the_publisher_skill_by_default(tmp_path):
    assert main(["init", "--dir", str(tmp_path)]) == 0
    assert skill_path(tmp_path, "ubag-publisher").exists()
    assert not skill_path(tmp_path, "ubag-agent").exists()


def test_the_agent_flag_writes_the_other_one(tmp_path):
    main(["init", "--agent", "--dir", str(tmp_path)])
    assert skill_path(tmp_path, "ubag-agent").exists()
    assert not skill_path(tmp_path, "ubag-publisher").exists()


def test_both_writes_both(tmp_path):
    main(["init", "--both", "--dir", str(tmp_path)])
    for name in SKILLS.values():
        assert skill_path(tmp_path, name).exists()


def test_the_skills_ship_with_the_package(tmp_path):
    """
    package-data, not packages.find.

    The templates are .md files inside the ubag package. setuptools carries
    Python modules automatically and data files only when told, so a wheel built
    without [tool.setuptools.package-data] installs _init_skill.py and no
    _skills/ directory, and init fails on a file that was never installed.
    """
    results = install(tmp_path, ["publisher", "agent"])
    for _, path, _ in results:
        assert path.read_text(encoding="utf-8").strip()


# ---------------------------------------------------------------------------
# Idempotence.
# ---------------------------------------------------------------------------

def test_running_it_twice_is_a_no_op(tmp_path):
    install(tmp_path, ["publisher"])
    again = install(tmp_path, ["publisher"])
    assert [outcome for _, _, outcome in again] == ["unchanged"]


def test_a_modified_skill_is_restored(tmp_path):
    """
    The skill file is ours and init owns it, unlike AGENTS.md which is theirs.

    Someone editing it locally has made a change that the next SDK upgrade would
    silently discard anyway, so saying "updated" out loud is the honest option.
    """
    install(tmp_path, ["publisher"])
    target = skill_path(tmp_path, "ubag-publisher")
    target.write_text("edited by hand\n", encoding="utf-8")
    assert [o for _, _, o in install(tmp_path, ["publisher"])] == ["updated"]
    assert "edited by hand" not in target.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# What it refuses to touch.
# ---------------------------------------------------------------------------

def test_an_existing_agents_md_is_never_modified(tmp_path, capsys):
    theirs = "# Our house rules\n\nDo not run migrations on Friday.\n"
    (tmp_path / "AGENTS.md").write_text(theirs, encoding="utf-8")

    main(["init", "--dir", str(tmp_path)])

    assert (tmp_path / "AGENTS.md").read_text(encoding="utf-8") == theirs
    out = capsys.readouterr().out
    assert "already exists and was not modified" in out
    # It has to tell them what to add, or the refusal is just a dead end.
    assert ".agents/skills/ubag-publisher/SKILL.md" in out


def test_an_existing_claude_md_is_never_modified(tmp_path, capsys):
    theirs = "@AGENTS.md\n<!-- plus our own notes -->\n"
    (tmp_path / "CLAUDE.md").write_text(theirs, encoding="utf-8")

    main(["init", "--dir", str(tmp_path)])

    assert (tmp_path / "CLAUDE.md").read_text(encoding="utf-8") == theirs
    assert "Confirm it reads AGENTS.md" in capsys.readouterr().out


def test_a_fresh_repo_gets_the_pointer_that_actually_works(tmp_path):
    """
    CLAUDE.md containing @AGENTS.md is the mechanism that was verified to pull
    the whole file into context. Nothing is written under .claude/skills,
    because that path's import semantics were not confirmed and a pointer that
    resolves to nothing is worse than no pointer at all.
    """
    main(["init", "--dir", str(tmp_path)])
    assert (tmp_path / "CLAUDE.md").read_text(encoding="utf-8") == "@AGENTS.md\n"
    assert ".agents/skills/ubag-publisher/SKILL.md" in \
        (tmp_path / "AGENTS.md").read_text(encoding="utf-8")
    assert not (tmp_path / ".claude").exists()


# ---------------------------------------------------------------------------
# Staleness.
# ---------------------------------------------------------------------------

def test_a_freshly_written_skill_is_not_stale(tmp_path):
    install(tmp_path, ["publisher", "agent"])
    assert check(tmp_path) == []


def test_an_old_skill_is_reported_stale(tmp_path):
    install(tmp_path, ["publisher"])
    target = skill_path(tmp_path, "ubag-publisher")
    target.write_text(
        target.read_text(encoding="utf-8").replace(
            f"ubag_skill_version: {__version__}", "ubag_skill_version: 0.1.0"),
        encoding="utf-8")
    assert check(tmp_path) == [("ubag-publisher", "0.1.0")]


def test_check_exits_nonzero_when_stale(tmp_path):
    install(tmp_path, ["agent"])
    target = skill_path(tmp_path, "ubag-agent")
    target.write_text("no frontmatter here\n", encoding="utf-8")
    assert main(["init", "--check", "--dir", str(tmp_path)]) == 1


def test_check_on_a_repo_with_no_skills_is_clean(tmp_path):
    """Absence is not staleness. Nothing installed, nothing to warn about."""
    assert check(tmp_path) == []
    assert main(["init", "--check", "--dir", str(tmp_path)]) == 0


def test_every_shipped_template_carries_a_version_stamp(tmp_path):
    """
    The staleness check reads this line. A template that ships without one makes
    check() report it as permanently stale, which trains people to ignore it.
    """
    for _, path, _ in install(tmp_path, list(SKILLS)):
        assert skill_version(path.read_text(encoding="utf-8")) == __version__


def test_the_version_is_not_a_hardcoded_literal_that_drifted():
    """
    __init__ said 0.5.0 while pyproject said 0.6.0, through a release. Harmless
    until init started stamping it into files and comparing them later.
    """
    import re
    from pathlib import Path

    # Read the line rather than parse the file. tomllib is 3.11+, this package
    # supports 3.10, and a test that skips on the oldest supported version is
    # not watching the runtime most likely to be somebody's system default.
    # One regex covers the whole matrix.
    pyproject = (Path(__file__).resolve().parents[1] / "pyproject.toml") \
        .read_text(encoding="utf-8")
    declared = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    assert declared, "pyproject.toml has no top-level version"
    assert __version__ == declared.group(1), (
        f"ubag.__version__ is {__version__}, pyproject says "
        f"{declared.group(1)}. When these disagree the installed package is not "
        f"this source tree, and `ubag init --check` reports skills stale that "
        f"are not.")
