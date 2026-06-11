#!/usr/bin/env python3
"""
paths.py — single source of truth for *where skills live*.

Both the scanner (`scan.py scan --all`), the install gate (`scan.py install`),
and the shell installer (`install.sh`) resolve install/search directories
through here, so the path list can never drift across the three call sites.

Targets (verified June 2026):
    ~/.claude/skills   Claude Code global skills dir.            [primary]
    ~/.codex/skills    Codex global skills dir.                  [primary]
    ~/.agents/skills   Emerging cross-agent neutral location.    [forward-looking]
    ~/.cursor/skills   Cursor's own global dir (newer only).     [fallback, opt-in]

`install_targets()` returns where a skill should be *copied to*. The Cursor
target is included only when `~/.cursor` already exists (matching install.sh).
`SKILLS_DIR` in the environment overrides every target with a single dir.

`search_dirs()` returns where to *look for already-installed skills* (used by
`scan --all`); it lists all four roots unconditionally — the caller filters to
the ones that exist.

CLI (so install.sh can consume the same logic):
    python paths.py --install-targets   # newline-separated install parents
    python paths.py --search-dirs        # newline-separated search parents
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Skill-search / install roots, in priority order.
_PRIMARY = ("~/.claude/skills", "~/.codex/skills")
_FORWARD = ("~/.agents/skills",)
_CURSOR = "~/.cursor/skills"


def _expand(p: str) -> Path:
    return Path(os.path.expanduser(p))


def install_targets() -> list[Path]:
    """Parent dirs a skill should be installed into (mirrors install.sh)."""
    override = os.environ.get("SKILLS_DIR")
    if override:
        return [Path(override)]
    targets = [_expand(p) for p in (*_PRIMARY, *_FORWARD)]
    if _expand("~/.cursor").is_dir():
        targets.append(_expand(_CURSOR))
    return targets


def search_dirs() -> list[Path]:
    """All known skill roots to enumerate for `scan --all` (existence-agnostic).

    Honors the same `SKILLS_DIR` override as `install_targets()`, so "install
    here" and "audit what's installed" stay pointed at the same place.
    """
    override = os.environ.get("SKILLS_DIR")
    if override:
        return [Path(override)]
    return [_expand(p) for p in (*_PRIMARY, *_FORWARD, _CURSOR)]


def installed_skills() -> list[Path]:
    """Every installed skill directory found under the existing search roots.

    A "skill directory" is any immediate child of a search root that contains a
    SKILL.md (case-insensitive). Deduplicated by resolved path so a skill that
    appears under several roots is only scanned once.
    """
    out: list[Path] = []
    seen: set[Path] = set()
    for root in search_dirs():
        if not root.is_dir():
            continue
        for child in sorted(root.iterdir()):
            if not child.is_dir():
                continue
            if not any(
                (child / name).is_file()
                for name in ("SKILL.md", "skill.md", "Skill.md")
            ):
                continue
            key = child.resolve()
            if key in seen:
                continue
            seen.add(key)
            out.append(child)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="paths.py")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--install-targets", action="store_true")
    g.add_argument("--search-dirs", action="store_true")
    g.add_argument("--installed-skills", action="store_true")
    args = ap.parse_args(argv)

    if args.install_targets:
        items = install_targets()
    elif args.search_dirs:
        items = search_dirs()
    else:
        items = installed_skills()
    for p in items:
        print(p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
