"""Immutable content snapshots shared by scanning, caching, and installation.

The scanner must never approve one filesystem view and install another.  This
module captures every in-policy regular file as immutable bytes, records the
disposition of everything else, and derives the content identity from that
single snapshot.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from . import archives
from .sanitize import safe_display

SCHEMA = "skill-auditor-content-manifest/v1"
MAX_TEXT_BYTES = 1_000_000
MAX_ENTRIES = 10_000
MAX_CAPTURED_BYTES = 50_000_000
MAX_TOTAL_BYTES = 500_000_000
MAX_DEPTH = 32

SCAN = "scan"
ARCHIVE = "archive"
SCAN_EXCLUDED = "scan-install-excluded"
ARCHIVE_EXCLUDED = "archive-install-excluded"
EXCLUDED = "excluded"
TRUSTED_BINARY = "trusted-binary-excluded"
BOUNDARY = "boundary"
INCOMPLETE = "incomplete"

_METADATA_DIRS = {
    ".git",
    ".pytest_cache",
    ".skill-auditor-cache",
    "__pycache__",
}
_INSTALL_EXCLUDED_DIRS = {
    ".github",
    ".idea",
    ".venv",
    "build",
    "dist",
    "node_modules",
    "tests",
    "venv",
}
_EXCLUDED_FILES = {
    ".skill-auditor.yaml",
    ".skill-auditor.yml",
    "skill-auditor.json",
    "skill-auditor.lock",
    "skill-auditor.md",
    "skill-auditor.sarif",
}
_EXCLUDED_SUFFIXES = {".pyc", ".pyo"}
_CONTROL_OR_BIDI_RE = re.compile(
    r"[\x00-\x1f\x7f-\x9f\ud800-\udfff\u202a-\u202e\u2066-\u2069]"
)
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


class ManifestError(ValueError):
    pass


class _EntryList(list):
    def __init__(self, issues: list["ManifestIssue"]) -> None:
        super().__init__()
        self.issues = issues
        self.total_bytes = 0
        self.captured_bytes = 0
        self.stopped = False

    def reject_size(self, size: int, path: str) -> bool:
        if self.stopped:
            return True
        if self.total_bytes + max(size, 0) > MAX_TOTAL_BYTES:
            self._stop(path, "snapshot exceeds the total byte traversal limit", "manifest-byte-limit")
            return True
        return False

    def append(self, item: "ManifestEntry") -> None:  # type: ignore[override]
        if self.stopped:
            return
        captured = len(item.content) if item.content is not None else 0
        if len(self) >= MAX_ENTRIES:
            self._stop(item.path, "snapshot contains too many entries", "manifest-entry-limit")
            return
        if self.total_bytes + max(item.size, 0) > MAX_TOTAL_BYTES:
            self._stop(item.path, "snapshot exceeds the total byte traversal limit", "manifest-byte-limit")
            return
        if self.captured_bytes + captured > MAX_CAPTURED_BYTES:
            self._stop(item.path, "snapshot exceeds the captured content limit", "manifest-capture-limit")
            return
        self.total_bytes += max(item.size, 0)
        self.captured_bytes += captured
        super().append(item)

    def _stop(self, path: str, message: str, code: str) -> None:
        if not self.stopped:
            self.issues.append(ManifestIssue(path, message, code))
        self.stopped = True


@dataclass(frozen=True)
class ManifestIssue:
    path: str
    message: str
    code: str = "unscanned-content"

    def as_dict(self) -> dict:
        return {"path": safe_display(self.path), "message": safe_display(self.message), "blocking": True, "code": self.code}


@dataclass(frozen=True)
class ManifestEntry:
    path: str
    kind: str
    size: int
    sha256: str
    disposition: str
    mode: int = 0o644
    content: bytes | None = field(default=None, repr=False, compare=False)
    detail: str | None = None

    @property
    def installable(self) -> bool:
        return self.disposition in {SCAN, ARCHIVE}

    @property
    def scannable(self) -> bool:
        return self.disposition in {
            SCAN,
            ARCHIVE,
            SCAN_EXCLUDED,
            ARCHIVE_EXCLUDED,
        }


@dataclass(frozen=True)
class ContentManifest:
    root: Path = field(compare=False)
    entries: tuple[ManifestEntry, ...]
    issues: tuple[ManifestIssue, ...]
    digest: str
    archive_target: bool = False

    @property
    def scan_status(self) -> str:
        return "INCOMPLETE" if self.issues else "COMPLETE"

    def entry(self, relative_path: str) -> ManifestEntry | None:
        portable = _portable(relative_path)
        return next((item for item in self.entries if item.path == portable), None)

    def install_entries(self) -> tuple[ManifestEntry, ...]:
        if self.scan_status != "COMPLETE":
            raise ManifestError("incomplete content snapshot cannot be installed")
        return tuple(item for item in self.entries if item.installable)

    def coverage(self) -> dict:
        counts: dict[str, int] = {}
        for entry in self.entries:
            counts[entry.disposition] = counts.get(entry.disposition, 0) + 1
        return {
            "manifest_schema": SCHEMA,
            "limits": {
                "max_entries": MAX_ENTRIES,
                "max_captured_bytes": MAX_CAPTURED_BYTES,
                "max_total_bytes": MAX_TOTAL_BYTES,
                "max_depth": MAX_DEPTH,
            },
            "entries": len(self.entries),
            "dispositions": dict(sorted(counts.items())),
            "excluded": [safe_display(item.path) for item in self.entries if item.disposition == EXCLUDED],
            "install_excluded": [
                safe_display(item.path)
                for item in self.entries
                if item.disposition in {SCAN_EXCLUDED, ARCHIVE_EXCLUDED}
            ],
            "trusted_binary_assets": [safe_display(item.path) for item in self.entries if item.disposition == TRUSTED_BINARY],
            "incomplete": [item.as_dict() for item in self.issues],
        }


def build(
    root: Path,
    *,
    ignored_path: Callable[[str], bool] | None = None,
    trusted_assets: Iterable[dict] = (),
    archive_target: bool = False,
) -> ContentManifest:
    """Capture a stable snapshot without following filesystem links."""

    ignored_path = ignored_path or (lambda _path: False)
    trusted = {
        _portable(str(item["path"])): str(item["sha256"]).lower()
        for item in trusted_assets
    }
    issues: list[ManifestIssue] = []
    entries: _EntryList = _EntryList(issues)
    matched_trusted: set[str] = set()

    try:
        root.lstat()
        if root.is_symlink() or _is_junction(root):
            raise ManifestError("content root must not be a symlink or junction")
        physical = root.resolve(strict=True)
    except ManifestError:
        raise
    except OSError as exc:
        raise ManifestError(f"cannot resolve content root: {safe_display(str(exc))}") from exc

    if archive_target:
        if not physical.is_file():
            raise ManifestError("archive snapshot target must be a regular file")
        if _unsafe_name(physical.name):
            entries.append(ManifestEntry(physical.name, "archive", 0, _empty_hash(), INCOMPLETE))
            issues.append(ManifestIssue(physical.name, "archive path contains control or bidirectional characters", "unsafe-path"))
        else:
            _capture_file(
                physical,
                physical.name,
                entries,
                issues,
                ignored_path,
                trusted,
                matched_trusted,
                force_archive=True,
            )
    elif physical.is_dir():
        _record_alternate_streams(physical, ".", issues)
        _walk(
            physical,
            physical,
            entries,
            issues,
            ignored_path,
            trusted,
            matched_trusted,
        )
    else:
        raise ManifestError("content root must be a directory or supported archive")

    for configured_path in sorted(set(trusted) - matched_trusted):
        issues.append(ManifestIssue(
            configured_path,
            "trusted binary asset does not match an existing binary file",
            "invalid-trusted-asset",
        ))

    ordered_entries = tuple(sorted(entries, key=lambda item: item.path))
    seen_paths: set[str] = set()
    for entry in ordered_entries:
        key = unicodedata.normalize("NFC", entry.path).casefold()
        if key in seen_paths:
            issues.append(ManifestIssue(
                entry.path,
                "path collides case-insensitively with another snapshot entry",
                "path-collision",
            ))
        seen_paths.add(key)
    ordered_issues = tuple(sorted(issues, key=lambda item: (item.path, item.code, item.message)))
    return ContentManifest(
        root=physical,
        entries=ordered_entries,
        issues=ordered_issues,
        digest=_digest(ordered_entries, ordered_issues, archive_target),
        archive_target=archive_target,
    )


def _walk(
    directory: Path,
    root: Path,
    entries: list[ManifestEntry],
    issues: list[ManifestIssue],
    ignored_path: Callable[[str], bool],
    trusted: dict[str, str],
    matched_trusted: set[str],
    depth: int = 0,
) -> None:
    if depth > MAX_DEPTH:
        issues.append(ManifestIssue(
            _relative(directory, root),
            "snapshot exceeds the directory depth limit",
            "manifest-depth-limit",
        ))
        return
    try:
        items = _bounded_scandir(directory, root, entries)
    except OSError as exc:
        relative = _relative(directory, root)
        issues.append(ManifestIssue(relative, f"cannot read directory: {safe_display(str(exc))}", "unreadable-directory"))
        return

    for item in items:
        if isinstance(entries, _EntryList) and entries.stopped:
            return
        path = Path(item.path)
        relative = _relative(path, root)
        if _unsafe_name(relative):
            entries.append(ManifestEntry(relative, "other", 0, _empty_hash(), INCOMPLETE))
            issues.append(ManifestIssue(relative, "path contains control or bidirectional characters", "unsafe-path"))
            continue
        try:
            linked = item.is_symlink() or _is_junction(path)
            if linked:
                _capture_link(path, relative, root, entries)
                continue
            if item.is_dir(follow_symlinks=False):
                _record_alternate_streams(path, relative, issues)
                if ignored_path(relative) or ignored_path(relative + "/"):
                    entries.append(ManifestEntry(relative, "directory", 0, _empty_hash(), EXCLUDED))
                    _walk_excluded(path, root, entries, issues, depth + 1)
                    continue
                if _metadata_directory(item.name):
                    entries.append(ManifestEntry(relative, "directory", 0, _empty_hash(), EXCLUDED))
                    _walk_excluded(path, root, entries, issues, depth + 1)
                    continue
                if _install_excluded_directory(item.name):
                    entries.append(ManifestEntry(
                        relative,
                        "directory",
                        0,
                        _empty_hash(),
                        EXCLUDED,
                        detail="contents are scanned but excluded from installation",
                    ))
                    _walk_install_excluded(
                        path,
                        root,
                        entries,
                        issues,
                        ignored_path,
                        trusted,
                        matched_trusted,
                        depth + 1,
                    )
                    continue
                _walk(
                    path,
                    root,
                    entries,
                    issues,
                    ignored_path,
                    trusted,
                    matched_trusted,
                    depth + 1,
                )
                continue
            if not item.is_file(follow_symlinks=False):
                entries.append(ManifestEntry(relative, "other", 0, _empty_hash(), INCOMPLETE))
                issues.append(ManifestIssue(relative, "non-regular filesystem entry cannot be inspected", "non-regular-file"))
                continue
            _capture_file(
                path,
                relative,
                entries,
                issues,
                ignored_path,
                trusted,
                matched_trusted,
            )
        except OSError as exc:
            entries.append(ManifestEntry(relative, "other", 0, _empty_hash(), INCOMPLETE))
            issues.append(ManifestIssue(relative, f"filesystem error: {safe_display(str(exc))}", "filesystem-error"))


def _bounded_scandir(
    directory: Path,
    root: Path,
    entries: list[ManifestEntry],
) -> list[os.DirEntry]:
    remaining = max(MAX_ENTRIES - len(entries), 0)
    collected: list[os.DirEntry] = []
    with os.scandir(directory) as iterator:
        for item in iterator:
            if len(collected) >= remaining:
                if isinstance(entries, _EntryList):
                    entries._stop(
                        _relative(directory, root),
                        "snapshot contains too many entries",
                        "manifest-entry-limit",
                    )
                return []
            collected.append(item)
    return sorted(collected, key=lambda item: item.name.lower())


def _walk_install_excluded(
    directory: Path,
    root: Path,
    entries: list[ManifestEntry],
    issues: list[ManifestIssue],
    ignored_path: Callable[[str], bool],
    trusted: dict[str, str],
    matched_trusted: set[str],
    depth: int = 0,
) -> None:
    """Scan a subtree while keeping every captured member out of the payload."""

    if depth > MAX_DEPTH:
        issues.append(ManifestIssue(
            _relative(directory, root),
            "snapshot exceeds the directory depth limit",
            "manifest-depth-limit",
        ))
        return
    try:
        items = _bounded_scandir(directory, root, entries)
    except OSError as exc:
        relative = _relative(directory, root)
        issues.append(ManifestIssue(
            relative,
            f"cannot read install-excluded directory: {safe_display(str(exc))}",
            "unreadable-directory",
        ))
        return
    for item in items:
        if isinstance(entries, _EntryList) and entries.stopped:
            return
        path = Path(item.path)
        relative = _relative(path, root)
        if _unsafe_name(relative):
            entries.append(ManifestEntry(
                relative, "other", 0, _empty_hash(), INCOMPLETE
            ))
            issues.append(ManifestIssue(
                relative,
                "install-excluded path contains unsafe characters",
                "unsafe-path",
            ))
            continue
        try:
            if item.is_symlink() or _is_junction(path):
                _capture_link(path, relative, root, entries)
            elif item.is_dir(follow_symlinks=False):
                _record_alternate_streams(path, relative, issues)
                if ignored_path(relative) or ignored_path(relative + "/"):
                    entries.append(ManifestEntry(
                        relative, "directory", 0, _empty_hash(), EXCLUDED
                    ))
                    _walk_excluded(path, root, entries, issues, depth + 1)
                elif _metadata_directory(item.name):
                    entries.append(ManifestEntry(
                        relative, "directory", 0, _empty_hash(), EXCLUDED
                    ))
                    _walk_excluded(path, root, entries, issues, depth + 1)
                else:
                    entries.append(ManifestEntry(
                        relative,
                        "directory",
                        0,
                        _empty_hash(),
                        EXCLUDED,
                        detail="contents are scanned but excluded from installation",
                    ))
                    _walk_install_excluded(
                        path,
                        root,
                        entries,
                        issues,
                        ignored_path,
                        trusted,
                        matched_trusted,
                        depth + 1,
                    )
            elif item.is_file(follow_symlinks=False):
                _capture_file(
                    path,
                    relative,
                    entries,
                    issues,
                    ignored_path,
                    trusted,
                    matched_trusted,
                    install_excluded=True,
                )
            else:
                entries.append(ManifestEntry(
                    relative, "other", 0, _empty_hash(), INCOMPLETE
                ))
                issues.append(ManifestIssue(
                    relative,
                    "install-excluded subtree contains a non-regular entry",
                    "non-regular-file",
                ))
        except OSError as exc:
            entries.append(ManifestEntry(
                relative, "other", 0, _empty_hash(), INCOMPLETE
            ))
            issues.append(ManifestIssue(
                relative,
                f"filesystem error in install-excluded subtree: {safe_display(str(exc))}",
                "filesystem-error",
            ))


def _walk_excluded(
    directory: Path,
    root: Path,
    entries: list[ManifestEntry],
    issues: list[ManifestIssue],
    depth: int = 0,
) -> None:
    """Record excluded subtrees completely without making them installable."""

    if depth > MAX_DEPTH:
        issues.append(ManifestIssue(
            _relative(directory, root),
            "snapshot exceeds the directory depth limit",
            "manifest-depth-limit",
        ))
        return
    try:
        items = _bounded_scandir(directory, root, entries)
    except OSError as exc:
        relative = _relative(directory, root)
        issues.append(ManifestIssue(relative, f"cannot read excluded directory: {safe_display(str(exc))}", "unreadable-directory"))
        return
    for item in items:
        if isinstance(entries, _EntryList) and entries.stopped:
            return
        path = Path(item.path)
        relative = _relative(path, root)
        if _unsafe_name(relative):
            entries.append(ManifestEntry(relative, "other", 0, _empty_hash(), INCOMPLETE))
            issues.append(ManifestIssue(relative, "excluded path contains control or bidirectional characters", "unsafe-path"))
            continue
        try:
            if item.is_symlink() or _is_junction(path):
                _capture_excluded_link(path, relative, entries, issues)
            elif item.is_dir(follow_symlinks=False):
                _record_alternate_streams(path, relative, issues)
                entries.append(ManifestEntry(relative, "directory", 0, _empty_hash(), EXCLUDED))
                _walk_excluded(path, root, entries, issues, depth + 1)
            elif item.is_file(follow_symlinks=False):
                _capture_excluded_file(path, relative, entries, issues)
            else:
                entries.append(ManifestEntry(relative, "other", 0, _empty_hash(), INCOMPLETE))
                issues.append(ManifestIssue(relative, "excluded subtree contains a non-regular entry", "non-regular-file"))
        except OSError as exc:
            entries.append(ManifestEntry(relative, "other", 0, _empty_hash(), INCOMPLETE))
            issues.append(ManifestIssue(relative, f"filesystem error in excluded subtree: {safe_display(str(exc))}", "filesystem-error"))


def _capture_excluded_file(
    path: Path,
    relative: str,
    entries: list[ManifestEntry],
    issues: list[ManifestIssue],
) -> None:
    stream_state = _windows_alternate_streams(path)
    _record_stream_state(relative, stream_state, issues)
    try:
        _capture_excluded_file_body(path, relative, entries, issues)
    finally:
        _record_stream_change(path, relative, stream_state, issues)


def _capture_excluded_file_body(
    path: Path,
    relative: str,
    entries: list[ManifestEntry],
    issues: list[ManifestIssue],
) -> None:
    try:
        before = path.lstat()
    except OSError as exc:
        entries.append(ManifestEntry(relative, "file", 0, _empty_hash(), INCOMPLETE))
        issues.append(ManifestIssue(relative, f"cannot stat excluded file: {safe_display(str(exc))}", "unreadable-file"))
        return
    if isinstance(entries, _EntryList) and entries.reject_size(before.st_size, relative):
        return
    checksum, changed, error = _hash_stream(path, before)
    disposition = INCOMPLETE if error or changed else EXCLUDED
    entries.append(ManifestEntry(
        relative,
        "file",
        before.st_size,
        checksum,
        disposition,
        mode=stat.S_IMODE(before.st_mode),
    ))
    if error or changed:
        issues.append(ManifestIssue(relative, error or "excluded file changed during snapshot", "unstable-file"))


def _capture_excluded_link(
    path: Path,
    relative: str,
    entries: list[ManifestEntry],
    issues: list[ManifestIssue],
) -> None:
    try:
        target = os.readlink(path)
        raw = target.encode("utf-8", "surrogatepass")
    except OSError as exc:
        target = safe_display(str(exc))
        raw = target.encode("utf-8", "replace")
    entries.append(ManifestEntry(
        relative,
        "link",
        len(raw),
        hashlib.sha256(raw).hexdigest(),
        INCOMPLETE,
        detail=safe_display(target),
    ))
    issues.append(ManifestIssue(relative, "excluded subtree contains a filesystem link", "excluded-link"))


def _capture_file(
    path: Path,
    relative: str,
    entries: list[ManifestEntry],
    issues: list[ManifestIssue],
    ignored_path: Callable[[str], bool],
    trusted: dict[str, str],
    matched_trusted: set[str],
    *,
    force_archive: bool = False,
    install_excluded: bool = False,
) -> None:
    stream_state = _windows_alternate_streams(path)
    _record_stream_state(relative, stream_state, issues)
    try:
        _capture_file_body(
            path,
            relative,
            entries,
            issues,
            ignored_path,
            trusted,
            matched_trusted,
            force_archive=force_archive,
            install_excluded=install_excluded,
        )
    finally:
        _record_stream_change(path, relative, stream_state, issues)


def _capture_file_body(
    path: Path,
    relative: str,
    entries: list[ManifestEntry],
    issues: list[ManifestIssue],
    ignored_path: Callable[[str], bool],
    trusted: dict[str, str],
    matched_trusted: set[str],
    *,
    force_archive: bool = False,
    install_excluded: bool = False,
) -> None:
    try:
        before = path.lstat()
    except OSError as exc:
        entries.append(ManifestEntry(relative, "file", 0, _empty_hash(), INCOMPLETE))
        issues.append(ManifestIssue(relative, f"cannot stat file: {safe_display(str(exc))}", "unreadable-file"))
        return

    size = before.st_size
    if isinstance(entries, _EntryList) and entries.reject_size(size, relative):
        return
    mode = stat.S_IMODE(before.st_mode)
    if _excluded_file(path.name) or ignored_path(relative):
        checksum, changed, error = _hash_stream(path, before)
        entries.append(ManifestEntry(relative, "file", size, checksum, EXCLUDED, mode=mode))
        if error or changed:
            issues.append(ManifestIssue(relative, error or "file changed while snapshot was created", "unstable-file"))
        return

    archive = force_archive or archives.is_archive(path)
    limit = archives.MAX_ARCHIVE_BYTES if archive else MAX_TEXT_BYTES
    if size > limit:
        checksum, changed, error = _hash_stream(path, before)
        binary = _binary_sample(path)
        expected = trusted.get(relative)
        if not archive and binary and expected and checksum == expected and not changed and not error:
            matched_trusted.add(relative)
            entries.append(ManifestEntry(relative, "binary", size, checksum, TRUSTED_BINARY, mode=mode))
            return
        if expected:
            matched_trusted.add(relative)
        entries.append(ManifestEntry(relative, "archive" if archive else "file", size, checksum, INCOMPLETE, mode=mode))
        message = error or (
            f"archive exceeds {archives.MAX_ARCHIVE_BYTES} byte inspection limit"
            if archive
            else f"file exceeds {MAX_TEXT_BYTES} byte text inspection limit"
        )
        if expected and checksum != expected:
            message = "trusted binary asset SHA-256 does not match"
        elif expected and not binary:
            message = "trusted asset is not demonstrably binary within the inspection sample"
        issues.append(ManifestIssue(relative, message, "oversized-content"))
        return

    try:
        content = _read_bounded(path, limit)
        after = path.lstat()
    except OSError as exc:
        entries.append(ManifestEntry(relative, "archive" if archive else "file", size, _empty_hash(), INCOMPLETE, mode=mode))
        issues.append(ManifestIssue(relative, f"cannot read file: {safe_display(str(exc))}", "unreadable-file"))
        return

    checksum = hashlib.sha256(content).hexdigest()
    if _changed(before, after) or len(content) != size or len(content) > limit:
        entries.append(ManifestEntry(relative, "archive" if archive else "file", len(content), checksum, INCOMPLETE, mode=mode))
        issues.append(ManifestIssue(relative, "file changed while snapshot was created", "unstable-file"))
        return
    if archive:
        disposition = ARCHIVE_EXCLUDED if install_excluded else ARCHIVE
        entries.append(ManifestEntry(
            relative,
            "archive",
            size,
            checksum,
            disposition,
            mode=mode,
            content=content,
        ))
        return

    try:
        text = content.decode("utf-8")
        binary = "\x00" in text
    except UnicodeError:
        binary = True
    if not binary:
        if relative in trusted:
            issues.append(ManifestIssue(relative, "trusted binary asset points to UTF-8 text", "invalid-trusted-asset"))
            entries.append(ManifestEntry(relative, "text", size, checksum, INCOMPLETE, mode=mode))
            matched_trusted.add(relative)
            return
        disposition = SCAN_EXCLUDED if install_excluded else SCAN
        entries.append(ManifestEntry(
            relative,
            "text",
            size,
            checksum,
            disposition,
            mode=mode,
            content=content,
        ))
        return


    expected = trusted.get(relative)
    if expected and checksum == expected:
        matched_trusted.add(relative)
        entries.append(ManifestEntry(relative, "binary", size, checksum, TRUSTED_BINARY, mode=mode))
        return
    if expected:
        matched_trusted.add(relative)
        message = "trusted binary asset SHA-256 does not match"
    else:
        message = "binary content cannot be inspected; pin it as a trusted asset to exclude it"
    entries.append(ManifestEntry(relative, "binary", size, checksum, INCOMPLETE, mode=mode))
    issues.append(ManifestIssue(relative, message, "uninspected-binary"))


def _capture_link(path: Path, relative: str, root: Path, entries: list[ManifestEntry]) -> None:
    try:
        target = os.readlink(path)
        raw = target.encode("utf-8", "surrogatepass")
    except OSError as exc:
        target = f"unreadable link: {safe_display(str(exc))}"
        raw = target.encode("utf-8", "replace")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
        rule_id = "BOUNDARY-002"
        detail = f"link resolves inside the skill root: {safe_display(str(resolved))}"
    except (OSError, RuntimeError, ValueError) as exc:
        rule_id = "BOUNDARY-001"
        detail = f"link escapes the skill root or is broken: {safe_display(str(exc))}"
    entries.append(ManifestEntry(
        relative,
        "link",
        len(raw),
        hashlib.sha256(raw).hexdigest(),
        BOUNDARY,
        detail=f"{rule_id}\0{detail}\0{safe_display(target)}",
    ))


def _record_alternate_streams(
    path: Path,
    relative: str,
    issues: list[ManifestIssue],
) -> None:
    _record_stream_state(relative, _windows_alternate_streams(path), issues)


def _record_stream_state(
    relative: str,
    state: tuple[tuple[str, ...], str | None],
    issues: list[ManifestIssue],
) -> None:
    streams, error = state
    if error:
        issues.append(ManifestIssue(
            relative,
            error,
            "alternate-stream-enumeration",
        ))
    for stream in streams:
        issues.append(ManifestIssue(
            relative,
            "filesystem entry has an uninspected alternate data stream: "
            + safe_display(stream),
            "alternate-data-stream",
        ))


def _record_stream_change(
    path: Path,
    relative: str,
    before: tuple[tuple[str, ...], str | None],
    issues: list[ManifestIssue],
) -> None:
    after = _windows_alternate_streams(path)
    if after == before:
        return
    issues.append(ManifestIssue(
        relative,
        "alternate data stream state changed while snapshot was created",
        "unstable-alternate-stream",
    ))
    before_streams, _before_error = before
    after_streams, after_error = after
    newly_visible = tuple(sorted(set(after_streams) - set(before_streams)))
    if after_error or newly_visible:
        _record_stream_state(relative, (newly_visible, after_error), issues)


def _windows_alternate_streams(path: Path) -> tuple[tuple[str, ...], str | None]:
    if os.name != "nt":
        return (), None
    try:
        import ctypes
        from ctypes import wintypes

        class Win32FindStreamData(ctypes.Structure):
            _fields_ = [
                ("stream_size", ctypes.c_longlong),
                ("stream_name", wintypes.WCHAR * 296),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        find_first = kernel32.FindFirstStreamW
        find_first.argtypes = [
            wintypes.LPCWSTR,
            ctypes.c_int,
            ctypes.POINTER(Win32FindStreamData),
            wintypes.DWORD,
        ]
        find_first.restype = wintypes.HANDLE
        find_next = kernel32.FindNextStreamW
        find_next.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(Win32FindStreamData),
        ]
        find_next.restype = wintypes.BOOL
        find_close = kernel32.FindClose
        find_close.argtypes = [wintypes.HANDLE]
        find_close.restype = wintypes.BOOL

        data = Win32FindStreamData()
        ctypes.set_last_error(0)
        handle = find_first(_windows_extended_path(path), 0, ctypes.byref(data), 0)
        invalid_handle = ctypes.c_void_p(-1).value
        if handle == invalid_handle:
            error_code = ctypes.get_last_error()
            if error_code == 38:  # ERROR_HANDLE_EOF: no named streams.
                return (), None
            return (), f"cannot enumerate alternate data streams (Windows error {error_code})"
        streams: list[str] = []
        try:
            while True:
                name = data.stream_name
                if name and name != "::$DATA":
                    streams.append(name)
                ctypes.set_last_error(0)
                if not find_next(handle, ctypes.byref(data)):
                    error_code = ctypes.get_last_error()
                    if error_code == 38:
                        break
                    return tuple(sorted(streams)), (
                        "cannot enumerate alternate data streams "
                        f"(Windows error {error_code})"
                    )
        finally:
            find_close(handle)
        return tuple(sorted(streams)), None
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        return (), "cannot enumerate alternate data streams: " + safe_display(exc)


def _windows_extended_path(path: Path) -> str:
    value = str(path.absolute())
    if value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _hash_stream(path: Path, before: os.stat_result) -> tuple[str, bool, str | None]:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as handle:
            remaining = max(before.st_size, 0) + 1
            while remaining:
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                total += len(chunk)
                remaining -= len(chunk)
        after = path.lstat()
    except OSError as exc:
        return _empty_hash(), False, f"cannot read file: {safe_display(str(exc))}"
    return (
        digest.hexdigest(),
        total != before.st_size or _changed(before, after),
        None,
    )


def _read_bounded(path: Path, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit + 1
    with path.open("rb") as handle:
        while remaining:
            chunk = handle.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    return b"".join(chunks)


def _binary_sample(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            sample = handle.read(8192)
        if b"\x00" in sample:
            return True
        sample.decode("utf-8")
        return False
    except UnicodeError:
        return True
    except OSError:
        return False


def _changed(before: os.stat_result, after: os.stat_result) -> bool:
    fields = ("st_size", "st_mtime_ns", "st_ino", "st_dev")
    return any(getattr(before, field, None) != getattr(after, field, None) for field in fields)


def _is_junction(path: Path) -> bool:
    checker = getattr(path, "is_junction", None)
    if checker is not None:
        try:
            return bool(checker())
        except OSError:
            return True
    try:
        attributes = path.lstat().st_file_attributes  # type: ignore[attr-defined]
        return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except AttributeError:
        return False
    except OSError:
        return True


def _metadata_directory(name: str) -> bool:
    lower = name.lower()
    return lower in _METADATA_DIRS or lower.endswith((".egg-info", ".dist-info"))


def _install_excluded_directory(name: str) -> bool:
    return name.lower() in _INSTALL_EXCLUDED_DIRS


def _excluded_file(name: str) -> bool:
    lower = name.lower()
    return lower in _EXCLUDED_FILES or Path(lower).suffix in _EXCLUDED_SUFFIXES


def _unsafe_name(relative: str) -> bool:
    if "\\" in relative or _CONTROL_OR_BIDI_RE.search(relative):
        return True
    parts = relative.split("/")
    return any(_unsafe_component(part) for part in parts)


def unsafe_relative_path(relative: str) -> bool:
    """Return whether a portable payload path is unsafe on any supported OS."""

    return _unsafe_name(relative)


def _unsafe_component(component: str) -> bool:
    if not component or component in {".", ".."} or ":" in component:
        return True
    if component.endswith((" ", ".")):
        return True
    return component.split(".", 1)[0].upper() in _WINDOWS_RESERVED


def _relative(path: Path, root: Path) -> str:
    try:
        return "/".join(path.relative_to(root).parts)
    except ValueError:
        return path.name


def _portable(value: str | Path) -> str:
    return str(value).replace("\\", "/")


def _digest(
    entries: tuple[ManifestEntry, ...],
    issues: tuple[ManifestIssue, ...],
    archive_target: bool,
) -> str:
    payload = {
        "schema": SCHEMA,
        "archive_target": archive_target,
        "limits": {
            "max_entries": MAX_ENTRIES,
            "max_captured_bytes": MAX_CAPTURED_BYTES,
            "max_total_bytes": MAX_TOTAL_BYTES,
            "max_depth": MAX_DEPTH,
        },
        "entries": [
            {
                "path": item.path,
                "kind": item.kind,
                "size": item.size,
                "sha256": item.sha256,
                "disposition": item.disposition,
                "mode": item.mode,
                "detail": item.detail,
            }
            for item in entries
        ],
        "issues": [
            {"path": item.path, "message": item.message, "code": item.code}
            for item in issues
        ],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8", "surrogatepass")
    return hashlib.sha256(encoded).hexdigest()


def _empty_hash() -> str:
    return hashlib.sha256(b"").hexdigest()
