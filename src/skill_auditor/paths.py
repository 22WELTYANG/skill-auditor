"""Cross-platform skill installation and discovery paths."""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path

_CLAUDE = "~/.claude/skills"
_LEGACY_CODEX = "~/.codex/skills"
_AGENTS = "~/.agents/skills"
_CURSOR = "~/.cursor/skills"
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
_SKILL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class PathSafetyError(ValueError):
    pass


def _expand(path: str) -> Path:
    return Path(os.path.expanduser(path))


def _default_dirs(*, include_cursor: bool) -> list[Path]:
    candidates: list[Path] = []
    codex_home = os.environ.get("CODEX_HOME")
    if codex_home:
        candidates.append(Path(codex_home).expanduser() / "skills")
    candidates.extend((_expand(_CLAUDE), _expand(_LEGACY_CODEX), _expand(_AGENTS)))
    if include_cursor:
        candidates.append(_expand(_CURSOR))
    return _deduplicate(candidates)


def _deduplicate(candidates: list[Path]) -> list[Path]:
    output: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            normalized = candidate.resolve(strict=False)
        except OSError:
            normalized = Path(os.path.abspath(candidate))
        key = os.path.normcase(str(normalized))
        if key in seen:
            continue
        seen.add(key)
        output.append(candidate)
    return output


def install_targets() -> list[Path]:
    override = os.environ.get("SKILLS_DIR")
    if override:
        return [Path(override).expanduser()]
    return _default_dirs(include_cursor=_expand("~/.cursor").is_dir())


def search_dirs() -> list[Path]:
    override = os.environ.get("SKILLS_DIR")
    if override:
        return [Path(override).expanduser()]
    return _default_dirs(include_cursor=True)


def validate_skill_name(name: str) -> str:
    if not name or name in {".", ".."}:
        raise PathSafetyError("skill name cannot be empty, '.' or '..'")
    if Path(name).is_absolute() or "/" in name or "\\" in name or ":" in name:
        raise PathSafetyError("skill name must not contain a path or drive prefix")
    if name.endswith((" ", ".")) or not _SKILL_NAME_RE.fullmatch(name):
        raise PathSafetyError("skill name contains unsupported characters")
    stem = name.split(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED:
        raise PathSafetyError(f"skill name is reserved on Windows: {name}")
    return name


def safe_install_destination(parent: Path, name: str) -> tuple[Path, Path]:
    safe_name = validate_skill_name(name)
    expanded = parent.expanduser()
    try:
        if expanded.exists() and (expanded.is_symlink() or _is_junction(expanded)):
            raise PathSafetyError(f"install root must not be a link: {expanded}")
        parent_resolved = expanded.resolve(strict=False)
    except OSError as exc:
        raise PathSafetyError(f"cannot resolve install root {parent}: {exc}") from exc
    if parent_resolved.exists() and (parent_resolved.is_symlink() or not parent_resolved.is_dir()):
        raise PathSafetyError(f"install root is not a regular directory: {parent_resolved}")
    destination = parent_resolved / safe_name
    try:
        destination.relative_to(parent_resolved)
    except ValueError as exc:
        raise PathSafetyError("install destination escapes the install root") from exc
    if destination == parent_resolved:
        raise PathSafetyError("install destination must be below the install root")
    return parent_resolved, destination


def _is_junction(path: Path) -> bool:
    checker = getattr(path, "is_junction", None)
    if checker is not None:
        try:
            return bool(checker())
        except OSError:
            return True
    try:
        attributes = path.lstat().st_file_attributes  # type: ignore[attr-defined]
        import stat
        return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except AttributeError:
        return False
    except OSError:
        return True


def installed_skills() -> list[Path]:
    output: list[Path] = []
    seen: set[Path] = set()
    for root in search_dirs():
        if not root.is_dir() or root.is_symlink():
            continue
        try:
            children = sorted(root.iterdir())
        except OSError:
            continue
        for child in children:
            if child.is_symlink() or not child.is_dir():
                continue
            try:
                names = [item.name.lower() for item in child.iterdir() if item.is_file()]
                key = child.resolve(strict=True)
            except OSError:
                continue
            if names.count("skill.md") != 1 or key in seen:
                continue
            seen.add(key)
            output.append(child)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="paths.py")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--install-targets", action="store_true")
    group.add_argument("--search-dirs", action="store_true")
    group.add_argument("--installed-skills", action="store_true")
    args = parser.parse_args(argv)
    if args.install_targets:
        items = install_targets()
    elif args.search_dirs:
        items = search_dirs()
    else:
        items = installed_skills()
    for item in items:
        print(item)
    return 0
