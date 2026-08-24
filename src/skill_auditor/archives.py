"""Read-only zip/tar inspection with bounded resource use."""

from __future__ import annotations

import re
import stat
import tarfile
import unicodedata
import zipfile
from io import BytesIO
from pathlib import Path, PurePosixPath

from .sanitize import safe_display

MAX_ARCHIVE_BYTES = 25_000_000
MAX_MEMBERS = 2_000
MAX_EXPANDED_BYTES = 100_000_000
MAX_MEMBER_BYTES = 1_000_000
MAX_COMPRESSION_RATIO = 200
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz")
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
class ArchiveError(ValueError):
    pass


def is_archive(path: Path) -> bool:
    lower = path.name.lower()
    return lower.endswith(ARCHIVE_SUFFIXES)


def inspect_archive(source: Path | bytes) -> tuple[list[dict], list[tuple[str, str]], list[dict]]:
    """Inspect an immutable archive buffer and fail with a controlled error."""

    raw = _archive_bytes(source)
    try:
        return _inspect_zip(raw)
    except zipfile.BadZipFile:
        pass
    except (OSError, EOFError, RuntimeError, ValueError) as exc:
        raise ArchiveError("cannot inspect zip archive") from exc
    try:
        return _inspect_tar(raw)
    except (tarfile.TarError, OSError, EOFError, RuntimeError, ValueError) as exc:
        raise ArchiveError("unsupported, invalid, or unreadable archive") from exc


def _archive_bytes(source: Path | bytes) -> bytes:
    if isinstance(source, bytes):
        if len(source) > MAX_ARCHIVE_BYTES:
            raise ArchiveError(f"archive exceeds {MAX_ARCHIVE_BYTES} bytes")
        return source
    try:
        if source.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ArchiveError(f"archive exceeds {MAX_ARCHIVE_BYTES} bytes")
        return source.read_bytes()
    except ArchiveError:
        raise
    except OSError as exc:
        raise ArchiveError("cannot read archive") from exc


def _inspect_zip(raw_archive: bytes):
    findings: list[dict] = []
    texts: list[tuple[str, str]] = []
    diagnostics: list[dict] = []
    total = 0
    seen: set[str] = set()
    with zipfile.ZipFile(BytesIO(raw_archive)) as archive:
        members = archive.infolist()
        _check_member_count(members)
        for member in members:
            raw_name = member.filename
            name = raw_name.replace("\\", "/")
            findings.extend(_member_name_findings(name))
            member_path = PurePosixPath(name)
            canonical = member_path.as_posix()
            comparable = name[:-1] if member.is_dir() and name.endswith("/") else name
            if (
                "\\" in raw_name
                or comparable != canonical
                or _unsafe_member_name(name)
            ):
                diagnostics.append(_diagnostic(name, "archive member path contains unsafe characters", "unsafe-archive-path"))
                continue
            name = canonical
            key = unicodedata.normalize("NFC", name).casefold()
            if key in seen:
                diagnostics.append(_diagnostic(name, "archive contains a duplicate member path", "duplicate-archive-path"))
                continue
            seen.add(key)
            total += member.file_size
            if total > MAX_EXPANDED_BYTES:
                findings.append(_archive_finding("ARCHIVE-004", name, "archive expansion limit exceeded"))
                diagnostics.append(_diagnostic(name, "archive expansion limit prevents complete inspection", "archive-expansion-limit"))
                break
            if _is_nested_archive(name):
                findings.append(_archive_finding(
                    "ARCHIVE-004", name, "nested archive skipped at the depth limit"
                ))
                diagnostics.append(_diagnostic(name, "nested archive cannot be inspected at the depth limit", "nested-archive"))
                continue
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode):
                findings.append(_archive_finding("ARCHIVE-002", name, "archive contains a symlink"))
                continue
            file_type = stat.S_IFMT(mode)
            if file_type and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                diagnostics.append(_diagnostic(name, "archive contains a special filesystem entry", "archive-special-member"))
                continue
            if member.flag_bits & 0x1:
                diagnostics.append(_diagnostic(name, "encrypted archive member cannot be inspected", "encrypted-archive-member"))
                continue
            if _looks_hidden_executable(name, mode):
                findings.append(_archive_finding("ARCHIVE-003", name, "hidden executable or hook member"))
            compressed = max(member.compress_size, 1)
            if member.file_size / compressed > MAX_COMPRESSION_RATIO:
                findings.append(_archive_finding("ARCHIVE-004", name, "suspicious compression ratio"))
            if member.is_dir():
                continue
            if member.file_size > MAX_MEMBER_BYTES:
                diagnostics.append(_diagnostic(name, f"archive member exceeds {MAX_MEMBER_BYTES} byte inspection limit", "archive-member-limit"))
                continue
            try:
                raw = archive.read(member)
                text = raw.decode("utf-8")
                if "\x00" in text:
                    raise UnicodeError("NUL byte")
                texts.append((name, text))
            except (OSError, UnicodeError, RuntimeError):
                diagnostics.append(_diagnostic(name, "archive member is not inspectable UTF-8 text", "uninspected-archive-member"))
    return findings, texts, diagnostics


def _inspect_tar(raw_archive: bytes):
    findings: list[dict] = []
    texts: list[tuple[str, str]] = []
    diagnostics: list[dict] = []
    total = 0
    seen: set[str] = set()
    with tarfile.open(fileobj=BytesIO(raw_archive), mode="r:*") as archive:
        members = archive.getmembers()
        _check_member_count(members)
        for member in members:
            raw_name = member.name
            name = raw_name.replace("\\", "/")
            findings.extend(_member_name_findings(name))
            member_path = PurePosixPath(name)
            canonical = member_path.as_posix()
            comparable = name[:-1] if member.isdir() and name.endswith("/") else name
            if (
                "\\" in raw_name
                or comparable != canonical
                or _unsafe_member_name(name)
            ):
                diagnostics.append(_diagnostic(name, "archive member path contains unsafe characters", "unsafe-archive-path"))
                continue
            name = canonical
            key = unicodedata.normalize("NFC", name).casefold()
            if key in seen:
                diagnostics.append(_diagnostic(name, "archive contains a duplicate member path", "duplicate-archive-path"))
                continue
            seen.add(key)
            total += member.size
            if total > MAX_EXPANDED_BYTES:
                findings.append(_archive_finding("ARCHIVE-004", name, "archive expansion limit exceeded"))
                diagnostics.append(_diagnostic(name, "archive expansion limit prevents complete inspection", "archive-expansion-limit"))
                break
            if _is_nested_archive(name):
                findings.append(_archive_finding(
                    "ARCHIVE-004", name, "nested archive skipped at the depth limit"
                ))
                diagnostics.append(_diagnostic(name, "nested archive cannot be inspected at the depth limit", "nested-archive"))
                continue
            if member.issym() or member.islnk():
                findings.append(_archive_finding("ARCHIVE-002", name, "archive contains a link"))
                continue
            if _looks_hidden_executable(name, member.mode):
                findings.append(_archive_finding("ARCHIVE-003", name, "hidden executable or hook member"))
            if member.isdir():
                continue
            if not member.isfile():
                diagnostics.append(_diagnostic(name, "archive contains a special filesystem entry", "archive-special-member"))
                continue
            if member.size > MAX_MEMBER_BYTES:
                diagnostics.append(_diagnostic(name, f"archive member exceeds {MAX_MEMBER_BYTES} byte inspection limit", "archive-member-limit"))
                continue
            handle = archive.extractfile(member)
            if handle is None:
                diagnostics.append(_diagnostic(name, "archive member cannot be read", "unreadable-archive-member"))
                continue
            try:
                text = handle.read().decode("utf-8")
                if "\x00" in text:
                    raise UnicodeError("NUL byte")
                texts.append((name, text))
            except (OSError, UnicodeError):
                diagnostics.append(_diagnostic(name, "archive member is not inspectable UTF-8 text", "uninspected-archive-member"))
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
    return {"rule_id": rule_id, "member": _safe_text(name), "message": _safe_text(message)}


def _diagnostic(path: str, message: str, code: str) -> dict:
    return {"path": _safe_text(path), "message": _safe_text(message), "blocking": True, "code": code}


def _unsafe_member_name(name: str) -> bool:
    if not name or re.search(
        r"[\x00-\x1f\x7f-\x9f\ud800-\udfff\u202a-\u202e\u2066-\u2069]", name
    ):
        return True
    return any(_unsafe_windows_component(part) for part in PurePosixPath(name).parts)


def _unsafe_windows_component(component: str) -> bool:
    if component in {".", ".."}:
        return False
    if not component or ":" in component or component.endswith((" ", ".")):
        return True
    return component.split(".", 1)[0].upper() in _WINDOWS_RESERVED


def _safe_text(value: str) -> str:
    return safe_display(value)
