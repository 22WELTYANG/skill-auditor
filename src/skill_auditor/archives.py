"""Read-only zip/tar inspection with bounded resource use."""

from __future__ import annotations

import io
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

MAX_ARCHIVE_BYTES = 25_000_000
MAX_MEMBERS = 2_000
MAX_EXPANDED_BYTES = 100_000_000
MAX_MEMBER_BYTES = 1_000_000
MAX_COMPRESSION_RATIO = 200
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz")
TEXT_SUFFIXES = {
    ".md", ".txt", ".sh", ".bash", ".zsh", ".fish", ".py", ".js", ".mjs",
    ".cjs", ".ts", ".ps1", ".bat", ".cmd", ".yaml", ".yml", ".json", ".toml",
    ".cfg", ".ini", ".env", "",
}


class ArchiveError(ValueError):
    pass


def is_archive(path: Path) -> bool:
    lower = path.name.lower()
    return lower.endswith(ARCHIVE_SUFFIXES)


def inspect_archive(path: Path) -> tuple[list[dict], list[tuple[str, str]], list[dict]]:
    try:
        if path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ArchiveError(f"archive exceeds {MAX_ARCHIVE_BYTES} bytes")
    except OSError as exc:
        raise ArchiveError(f"cannot stat archive: {exc}") from exc
    if zipfile.is_zipfile(path):
        return _inspect_zip(path)
    if tarfile.is_tarfile(path):
        return _inspect_tar(path)
    raise ArchiveError("unsupported or invalid archive")


def _inspect_zip(path: Path):
    findings: list[dict] = []
    texts: list[tuple[str, str]] = []
    diagnostics: list[dict] = []
    total = 0
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        _check_member_count(members)
        for member in members:
            name = member.filename.replace("\\", "/")
            total += member.file_size
            if total > MAX_EXPANDED_BYTES:
                findings.append(_archive_finding("ARCHIVE-004", name, "archive expansion limit exceeded"))
                break
            findings.extend(_member_name_findings(name))
            if _is_nested_archive(name):
                findings.append(_archive_finding(
                    "ARCHIVE-004", name, "nested archive skipped at the depth limit"
                ))
                continue
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode):
                findings.append(_archive_finding("ARCHIVE-002", name, "archive contains a symlink"))
                continue
            if _looks_hidden_executable(name, mode):
                findings.append(_archive_finding("ARCHIVE-003", name, "hidden executable or hook member"))
            compressed = max(member.compress_size, 1)
            if member.file_size / compressed > MAX_COMPRESSION_RATIO:
                findings.append(_archive_finding("ARCHIVE-004", name, "suspicious compression ratio"))
            if member.is_dir() or member.file_size > MAX_MEMBER_BYTES:
                continue
            if PurePosixPath(name).suffix.lower() not in TEXT_SUFFIXES:
                continue
            try:
                raw = archive.read(member)
                texts.append((name, raw.decode("utf-8")))
            except (OSError, UnicodeError, RuntimeError):
                diagnostics.append({"path": name, "message": "archive member is not readable UTF-8 text"})
    return findings, texts, diagnostics


def _inspect_tar(path: Path):
    findings: list[dict] = []
    texts: list[tuple[str, str]] = []
    diagnostics: list[dict] = []
    total = 0
    with tarfile.open(path, mode="r:*") as archive:
        members = archive.getmembers()
        _check_member_count(members)
        for member in members:
            name = member.name.replace("\\", "/")
            total += member.size
            if total > MAX_EXPANDED_BYTES:
                findings.append(_archive_finding("ARCHIVE-004", name, "archive expansion limit exceeded"))
                break
            findings.extend(_member_name_findings(name))
            if _is_nested_archive(name):
                findings.append(_archive_finding(
                    "ARCHIVE-004", name, "nested archive skipped at the depth limit"
                ))
                continue
            if member.issym() or member.islnk():
                findings.append(_archive_finding("ARCHIVE-002", name, "archive contains a link"))
                continue
            if _looks_hidden_executable(name, member.mode):
                findings.append(_archive_finding("ARCHIVE-003", name, "hidden executable or hook member"))
            if not member.isfile() or member.size > MAX_MEMBER_BYTES:
                continue
            if PurePosixPath(name).suffix.lower() not in TEXT_SUFFIXES:
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            try:
                texts.append((name, handle.read().decode("utf-8")))
            except (OSError, UnicodeError):
                diagnostics.append({"path": name, "message": "archive member is not readable UTF-8 text"})
    return findings, texts, diagnostics


def validate_archive_skill(texts: list[tuple[str, str]]) -> str:
    skill_paths = [name for name, _ in texts if PurePosixPath(name).name.lower() == "skill.md"]
    if len(skill_paths) != 1:
        raise ArchiveError("archive must contain exactly one SKILL.md")
    skill_path = PurePosixPath(skill_paths[0])
    return "" if str(skill_path.parent) == "." else str(skill_path.parent) + "/"


def _check_member_count(members) -> None:
    if len(members) > MAX_MEMBERS:
        raise ArchiveError(f"archive has more than {MAX_MEMBERS} members")


def _member_name_findings(name: str) -> list[dict]:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or _looks_windows_absolute(name):
        return [_archive_finding("ARCHIVE-001", name, "archive member escapes its extraction root")]
    return []


def _looks_windows_absolute(name: str) -> bool:
    return len(name) >= 3 and name[1] == ":" and name[2] in "/\\"


def _is_nested_archive(name: str) -> bool:
    lower = name.lower()
    return lower.endswith(ARCHIVE_SUFFIXES)


def _looks_hidden_executable(name: str, mode: int) -> bool:
    lower = name.lower()
    hook_names = {
        "pre-commit", "post-checkout", "post-merge", "post-rewrite",
        "pre-push", "commit-msg", "prepare-commit-msg",
    }
    return (
        "/.git/hooks/" in "/" + lower
        or PurePosixPath(lower).name in hook_names
        or ((mode & 0o111) and PurePosixPath(lower).suffix in {".sh", ".py", ".js", ".ps1", ""})
    )


def _archive_finding(rule_id: str, name: str, message: str) -> dict:
    return {"rule_id": rule_id, "member": name, "message": message}
