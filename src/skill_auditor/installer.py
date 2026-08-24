"""Manifest-driven, transactional installation for Agent Skills.

The installer deliberately does not walk an untrusted source tree.  Callers
must pass the exact regular files approved by the scanner's immutable content
manifest.  The self-installer has a separate Git-backed payload builder so a
local checkout cannot smuggle untracked build output into an installation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping

from . import paths
from .sanitize import safe_display


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UNSAFE_TEXT_RE = re.compile(
    r"[\x00-\x1f\x7f-\x9f\ud800-\udfff\u202a-\u202e\u2066-\u2069]"
)
_SELF_ROOT_FILES = frozenset({"LICENSE", "SKILL.md", "pyproject.toml"})
_SELF_DIRECTORIES = frozenset(
    {"agents", "references", "rules", "schemas", "scripts", "src"}
)
_SELF_SCRIPT_FILES = frozenset(
    {
        "config.py",
        "formats.py",
        "paths.py",
        "render_catalog.py",
        "rules_loader.py",
        "scan.py",
        "skill_auditor.py",
    }
)
_BUILD_DIRECTORIES = frozenset(
    {".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__", "build", "dist"}
)
_BUILD_SUFFIXES = (".pyc", ".pyo")
PAYLOAD_MANIFEST = "skill-auditor-payload.json"
PAYLOAD_SCHEMA = "skill-auditor-install-payload/v1"
LOCAL_GIT_TIMEOUT_SECONDS = 30
_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


class InstallError(RuntimeError):
    """A controlled installation failure."""


@dataclass(frozen=True)
class PayloadEntry:
    """One scanner-approved regular file in the installation payload."""

    path: str
    size: int
    sha256: str
    mode: int
    content: bytes

    def __post_init__(self) -> None:
        normalized = _safe_relative_path(self.path)
        if normalized != self.path:
            object.__setattr__(self, "path", normalized)
        if isinstance(self.size, bool) or not isinstance(self.size, int) or self.size < 0:
            raise InstallError(f"invalid payload size for {normalized}")
        digest = self.sha256.lower()
        if not _SHA256_RE.fullmatch(digest):
            raise InstallError(f"invalid payload SHA-256 for {normalized}")
        object.__setattr__(self, "sha256", digest)
        if isinstance(self.mode, bool) or not isinstance(self.mode, int):
            raise InstallError(f"invalid payload mode for {normalized}")
        object.__setattr__(self, "mode", self.mode & 0o777)
        if not isinstance(self.content, bytes):
            raise InstallError(f"payload content is missing for {normalized}")
        if (
            len(self.content) != self.size
            or hashlib.sha256(self.content).hexdigest() != digest
        ):
            raise InstallError(f"payload bytes do not match the snapshot: {normalized}")

    @classmethod
    def from_manifest(cls, value: object) -> "PayloadEntry":
        """Adapt a manifest mapping without enumerating the source tree."""

        if isinstance(value, cls):
            return value
        try:
            if isinstance(value, Mapping):
                path_value = value.get("path", value.get("relative_path"))
                size_value = value["size"]
                digest_value = value.get("sha256", value.get("digest"))
                mode_value = value.get("mode", 0o644)
                content_value = value.get("content")
            else:
                path_value = getattr(value, "path", getattr(value, "relative_path", None))
                size_value = getattr(value, "size")
                digest_value = getattr(value, "sha256", getattr(value, "digest", None))
                mode_value = getattr(value, "mode", 0o644)
                content_value = getattr(value, "content")
            if not isinstance(path_value, str) or not isinstance(content_value, bytes):
                raise TypeError
            return cls(
                path=path_value,
                size=int(size_value),
                sha256=str(digest_value),
                mode=int(mode_value),
                content=content_value,
            )
        except (AttributeError, KeyError, TypeError, ValueError) as exc:
            raise InstallError(
                "payload entry requires captured path, size, sha256, mode, and content"
            ) from exc


@dataclass
class _PreparedInstall:
    parent: Path
    destination: Path
    staging: Path
    backup: Path
    backup_moved: bool = False
    installed: bool = False


# Kept as a seam for deterministic rollback tests.
_replace = os.replace


def install_snapshot(
    entries: Iterable[object],
    name: str,
    *,
    targets: Iterable[Path] | None = None,
) -> list[Path]:
    """Install exactly the captured bytes in ``entries`` as one transaction.

    Every target is fully staged and hash-verified before any existing install
    is replaced.  A commit failure restores all prior destinations, including
    targets already committed earlier in the transaction.
    """

    try:
        safe_name = paths.validate_skill_name(name)
    except paths.PathSafetyError as exc:
        raise InstallError(str(exc)) from exc
    payload = _validate_payload(entries)
    if not payload:
        raise InstallError("installation payload is empty")
    if not any(entry.path.casefold() == "skill.md" for entry in payload):
        raise InstallError("installation snapshot does not contain SKILL.md")

    requested_targets = list(paths.install_targets() if targets is None else targets)
    if not requested_targets:
        raise InstallError("no installation targets were selected")
    prepared: list[_PreparedInstall] = []
    seen_destinations: set[str] = set()
    try:
        for requested in requested_targets:
            parent, destination = paths.safe_install_destination(
                Path(requested), safe_name
            )
            destination_key = os.path.normcase(str(destination))
            if destination_key in seen_destinations:
                continue
            seen_destinations.add(destination_key)
            parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() and (
                _is_link(destination) or not destination.is_dir()
            ):
                raise InstallError(f"refusing to replace unsafe destination: {destination}")
            staging = Path(
                tempfile.mkdtemp(prefix=f".{safe_name}.staging-", dir=parent)
            )
            item = _PreparedInstall(
                parent=parent,
                destination=destination,
                staging=staging,
                backup=parent / f".{safe_name}.backup-{uuid.uuid4().hex}",
            )
            prepared.append(item)
            _stage_payload(staging, payload)

        for item in prepared:
            _verify_staging(item.staging, payload)

        for item in prepared:
            if item.destination.exists():
                _replace(item.destination, item.backup)
                item.backup_moved = True
            _replace(item.staging, item.destination)
            item.installed = True
    except (InstallError, OSError, paths.PathSafetyError) as exc:
        rollback_errors = _rollback(prepared)
        detail = str(exc)
        if rollback_errors:
            detail += "; rollback incomplete: " + "; ".join(rollback_errors)
        raise InstallError(detail) from exc

    for item in prepared:
        if item.backup_moved and item.backup.exists():
            shutil.rmtree(item.backup, ignore_errors=True)
    return [item.destination for item in prepared]


def self_payload(source: Path) -> tuple[PayloadEntry, ...]:
    """Capture and verify the Agent Skill payload from one immutable commit."""

    try:
        root = source.expanduser().resolve(strict=True)
    except OSError as exc:
        raise InstallError(f"cannot resolve self-install source: {exc}") from exc
    commit = _fixed_head(root)
    _assert_clean_self_payload(root, commit)
    tracked = _head_self_paths(root, commit)
    entries = tuple(_entry_from_head(root, commit, relative) for relative in tracked)
    if not any(entry.path == "SKILL.md" for entry in entries):
        raise InstallError("fixed release checkout does not contain tracked SKILL.md")
    expected = _read_payload_manifest(root, commit)
    actual = {
        entry.path: {"size": entry.size, "sha256": entry.sha256}
        for entry in entries
    }
    if actual != expected:
        raise InstallError(
            f"{PAYLOAD_MANIFEST} does not match the tracked Agent Skill payload"
        )
    return entries


def _fixed_head(root: Path) -> str:
    result = _run_local_git(root, ["rev-parse", "--verify", "HEAD^{commit}"])
    if result.returncode:
        raise InstallError("self-install requires a fixed Git commit")
    try:
        commit = result.stdout.decode("ascii").strip().lower()
    except UnicodeDecodeError as exc:
        raise InstallError("fixed Git commit has an invalid object id") from exc
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", commit):
        raise InstallError("fixed Git commit has an invalid object id")
    return commit


def _assert_clean_self_payload(root: Path, commit: str) -> None:
    scope = [PAYLOAD_MANIFEST, *sorted(_SELF_ROOT_FILES), *sorted(_SELF_DIRECTORIES)]
    commands = (
        ["diff", "--quiet", "--no-ext-diff", "--no-textconv", commit, "--", *scope],
        [
            "diff",
            "--cached",
            "--quiet",
            "--no-ext-diff",
            "--no-textconv",
            commit,
            "--",
            *scope,
        ],
    )
    if any(_run_local_git(root, command).returncode for command in commands):
        raise InstallError(
            "self-install payload differs from the reviewed fixed commit"
        )


def _head_self_paths(root: Path, commit: str) -> tuple[str, ...]:
    result = _run_local_git(
        root,
        [
            "ls-tree",
            "-r",
            "-z",
            "--name-only",
            commit,
            "--",
            *sorted(_SELF_ROOT_FILES),
            *sorted(_SELF_DIRECTORIES),
        ],
    )
    if result.returncode:
        raise InstallError("cannot inspect the fixed release commit")
    output: list[str] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            relative = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InstallError("fixed payload path is not valid UTF-8") from exc
        pure = PurePosixPath(relative)
        if _is_self_payload_path(pure):
            output.append(_safe_relative_path(pure.as_posix()))
    return tuple(sorted(output))


def build_payload_manifest(source: Path, *, include_untracked: bool = False) -> dict:
    """Return checksums for the Git-canonical form of the reviewed payload.

    The real index is read without applying working-tree filters or executing
    configured clean processes.  Maintainers must stage payload changes before
    regenerating the manifest.  This keeps the result stable when a Windows
    checkout presents CRLF bytes while the committed blobs use LF.
    """

    try:
        root = source.expanduser().resolve(strict=True)
    except OSError as exc:
        raise InstallError(f"cannot resolve self-install source: {exc}") from exc
    entries = _canonical_payload_entries(
        root, include_untracked=include_untracked
    )
    return {
        "schema": PAYLOAD_SCHEMA,
        "files": [
            {"path": entry.path, "size": entry.size, "sha256": entry.sha256}
            for entry in entries
        ],
    }


def write_payload_manifest(
    source: Path,
    destination: Path | None = None,
    *,
    include_untracked: bool = False,
) -> Path:
    """Atomically write the self-install checksum manifest for maintainers."""

    root = source.expanduser().resolve(strict=True)
    output = destination or (root / PAYLOAD_MANIFEST)
    data = json.dumps(
        build_payload_manifest(root, include_untracked=include_untracked),
        indent=2,
        ensure_ascii=False,
        sort_keys=True,
    ) + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.tmp-{uuid.uuid4().hex}")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(data)
        os.replace(temporary, output)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise InstallError(f"cannot write {PAYLOAD_MANIFEST}: {exc}") from exc
    return output


def _tracked_self_paths(
    root: Path, *, include_untracked: bool = False
) -> tuple[str, ...]:
    command = [
        "git",
        "-c",
        f"safe.directory={root.as_posix()}",
        "-C",
        str(root),
        "ls-files",
        "--cached",
        *(["--others", "--exclude-standard"] if include_untracked else []),
        "-z",
        "--",
        *_SELF_ROOT_FILES,
        *_SELF_DIRECTORIES,
    ]
    try:
        result = subprocess.run(command, capture_output=True, check=False)
    except OSError as exc:
        raise InstallError(f"cannot inspect the fixed release checkout: {exc}") from exc
    if result.returncode:
        raise InstallError(
            "self-install requires a Git checkout at a reviewed, fixed release"
        )
    output: list[str] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        try:
            relative = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InstallError("tracked payload path is not valid UTF-8") from exc
        pure = PurePosixPath(relative)
        if not _is_self_payload_path(pure):
            continue
        output.append(pure.as_posix())
    return tuple(sorted(output))


def _canonical_payload_entries(
    root: Path, *, include_untracked: bool
) -> tuple[PayloadEntry, ...]:
    tracked = _tracked_self_paths(root)
    if include_untracked:
        combined = _tracked_self_paths(root, include_untracked=True)
        untracked = sorted(set(combined) - set(tracked))
        if untracked:
            raise InstallError(
                f"payload file must be staged before manifest generation: {untracked[0]}"
            )
    if not tracked:
        return ()
    listed = _run_local_git(
        root,
        ["ls-files", "--stage", "-z", "--", *tracked],
    )
    if listed.returncode:
        raise InstallError("cannot inspect the canonical payload index")
    entries = [
        _entry_from_index_record(root, record)
        for record in listed.stdout.split(b"\0")
        if record
    ]
    return _validate_payload(entries)


def _entry_from_index_record(root: Path, record: bytes) -> PayloadEntry:
    if b"\t" not in record:
        raise InstallError("canonical payload index contains an invalid entry")
    metadata, raw_path = record.split(b"\t", 1)
    fields = metadata.split()
    if len(fields) != 3 or fields[2] != b"0":
        raise InstallError("canonical payload index contains an unresolved entry")
    mode, object_id, _stage = fields
    if mode not in {b"100644", b"100755"}:
        raise InstallError("canonical payload entry is not a regular file")
    try:
        relative = raw_path.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InstallError("canonical payload path is not valid UTF-8") from exc
    normalized = _safe_relative_path(relative)
    if not _is_self_payload_path(PurePosixPath(normalized)):
        raise InstallError("canonical payload index contains an unexpected path")
    content_result = _run_local_git(
        root,
        ["cat-file", "blob", object_id.decode("ascii")],
    )
    if content_result.returncode:
        raise InstallError(f"cannot read canonical payload file {normalized}")
    content = content_result.stdout
    return PayloadEntry(
        normalized,
        len(content),
        hashlib.sha256(content).hexdigest(),
        0o755 if mode == b"100755" else 0o644,
        content,
    )
def _read_payload_manifest(
    root: Path, commit: str
) -> dict[str, dict[str, object]]:
    result = _run_local_git(
        root,
        ["cat-file", "blob", f"{commit}:{PAYLOAD_MANIFEST}"],
    )
    if result.returncode:
        raise InstallError(f"{PAYLOAD_MANIFEST} must exist in the fixed commit")
    try:
        raw = result.stdout.decode("utf-8")
        data = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise InstallError(f"cannot read {PAYLOAD_MANIFEST}: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema") != PAYLOAD_SCHEMA:
        raise InstallError(f"unsupported {PAYLOAD_MANIFEST} schema")
    files = data.get("files")
    if not isinstance(files, list):
        raise InstallError(f"{PAYLOAD_MANIFEST} files must be a list")
    output: dict[str, dict[str, object]] = {}
    seen_keys: set[str] = set()
    for value in files:
        if not isinstance(value, dict) or set(value) != {"path", "size", "sha256"}:
            raise InstallError(f"invalid entry in {PAYLOAD_MANIFEST}")
        path_value = value.get("path")
        size_value = value.get("size")
        digest_value = value.get("sha256")
        if (
            not isinstance(path_value, str)
            or isinstance(size_value, bool)
            or not isinstance(size_value, int)
            or size_value < 0
            or not isinstance(digest_value, str)
            or not _SHA256_RE.fullmatch(digest_value)
        ):
            raise InstallError(f"invalid entry in {PAYLOAD_MANIFEST}")
        normalized = _safe_relative_path(path_value)
        key = _portable_path_key(normalized)
        if key in seen_keys:
            raise InstallError(f"duplicate path in {PAYLOAD_MANIFEST}: {normalized}")
        seen_keys.add(key)
        output[normalized] = {"size": size_value, "sha256": digest_value}
    return output


def _entry_from_head(root: Path, commit: str, relative: str) -> PayloadEntry:
    tree = _run_local_git(root, ["ls-tree", "-z", commit, "--", relative])
    if tree.returncode or not tree.stdout.endswith(b"\0"):
        raise InstallError(f"cannot inspect fixed payload file {relative}")
    records = [record for record in tree.stdout.split(b"\0") if record]
    if len(records) != 1 or b"\t" not in records[0]:
        raise InstallError(f"fixed payload entry is ambiguous: {relative}")
    metadata, raw_path = records[0].split(b"\t", 1)
    fields = metadata.split()
    if len(fields) != 3 or fields[1] != b"blob" or fields[0] not in {b"100644", b"100755"}:
        raise InstallError(f"fixed payload entry is not a regular file: {relative}")
    try:
        listed_path = raw_path.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InstallError("fixed payload path is not valid UTF-8") from exc
    if listed_path != relative:
        raise InstallError(f"fixed payload entry is ambiguous: {relative}")
    content_result = _run_local_git(
        root,
        ["cat-file", "blob", f"{commit}:{relative}"],
    )
    if content_result.returncode:
        raise InstallError(f"cannot read fixed payload file {relative}")
    content = content_result.stdout
    mode = 0o755 if fields[0] == b"100755" else 0o644
    return PayloadEntry(
        relative,
        len(content),
        hashlib.sha256(content).hexdigest(),
        mode,
        content,
    )


def _run_local_git(root: Path, arguments: list[str]):
    environment = os.environ.copy()
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    try:
        return subprocess.run(
            [
                "git",
                "-c",
                f"safe.directory={root.as_posix()}",
                "-C",
                str(root),
                *arguments,
            ],
            capture_output=True,
            check=False,
            env=environment,
            timeout=LOCAL_GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallError("cannot inspect the fixed release checkout") from exc


def _validate_payload(
    entries: Iterable[object],
) -> tuple[PayloadEntry, ...]:
    output: list[PayloadEntry] = []
    seen: set[str] = set()
    for value in entries:
        entry = PayloadEntry.from_manifest(value)
        key = _portable_path_key(entry.path)
        if key in seen:
            raise InstallError(f"duplicate payload path: {entry.path}")
        seen.add(key)
        output.append(entry)
    output.sort(key=lambda entry: entry.path)
    paths_only = {_portable_path_key(entry.path) for entry in output}
    for entry in output:
        path_value = entry.path
        parts = PurePosixPath(path_value).parts
        for index in range(1, len(parts)):
            parent_key = _portable_path_key(
                PurePosixPath(*parts[:index]).as_posix()
            )
            if parent_key in paths_only:
                raise InstallError(f"payload has a file/directory conflict: {path_value}")
    return tuple(output)


def _stage_payload(staging: Path, payload: tuple[PayloadEntry, ...]) -> None:
    for entry in payload:
        relative = PurePosixPath(entry.path)
        destination = staging.joinpath(*relative.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            with destination.open("xb") as output:
                output.write(entry.content)
            os.chmod(destination, entry.mode)
        except OSError as exc:
            raise InstallError(f"cannot stage payload file {entry.path}: {exc}") from exc


def _verify_staging(staging: Path, payload: tuple[PayloadEntry, ...]) -> None:
    expected = {entry.path: entry for entry in payload}
    actual: set[str] = set()
    try:
        for directory, dirnames, filenames in os.walk(staging, followlinks=False):
            base = Path(directory)
            for name in dirnames:
                candidate = base / name
                if _is_link(candidate):
                    raise InstallError("staging contains a filesystem link")
            for name in filenames:
                candidate = base / name
                relative = candidate.relative_to(staging).as_posix()
                if _is_link(candidate):
                    raise InstallError(f"staged payload entry is a link: {relative}")
                details = candidate.lstat()
                if not stat.S_ISREG(details.st_mode):
                    raise InstallError(
                        f"staged payload entry is not a regular file: {relative}"
                    )
                entry = expected.get(relative)
                if entry is None:
                    raise InstallError(f"staging contains an unexpected file: {relative}")
                digest = hashlib.sha256()
                with candidate.open("rb") as handle:
                    for block in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(block)
                if details.st_size != entry.size or digest.hexdigest() != entry.sha256:
                    raise InstallError(f"staged payload bytes do not match: {relative}")
                actual.add(relative)
    except OSError as exc:
        raise InstallError(f"cannot verify staged payload: {exc}") from exc
    if actual != set(expected):
        missing = sorted(set(expected) - actual)
        raise InstallError(f"staged payload is missing a file: {missing[0]}")


def _rollback(prepared: list[_PreparedInstall]) -> list[str]:
    errors: list[str] = []
    for item in reversed(prepared):
        try:
            if item.installed and item.destination.exists():
                shutil.rmtree(item.destination)
            if item.backup_moved and item.backup.exists():
                _replace(item.backup, item.destination)
                item.backup_moved = False
        except OSError as exc:
            errors.append(f"{item.destination}: {exc}")
    for item in prepared:
        if item.staging.exists():
            shutil.rmtree(item.staging, ignore_errors=True)
        if item.backup.exists() and not item.backup_moved:
            shutil.rmtree(item.backup, ignore_errors=True)
    return errors


def _entry_from_file(root: Path, relative: str) -> PayloadEntry:
    path = root.joinpath(*PurePosixPath(relative).parts)
    if _has_link_component(root, PurePosixPath(relative)):
        raise InstallError(f"tracked payload file is a link: {relative}")
    try:
        content = path.read_bytes()
    except OSError as exc:
        raise InstallError(f"cannot read tracked payload file {relative}: {exc}") from exc
    if not path.is_file():
        raise InstallError(f"tracked payload entry is not a regular file: {relative}")
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError as exc:
        raise InstallError(f"cannot stat tracked payload file {relative}: {exc}") from exc
    return PayloadEntry(
        relative,
        len(content),
        hashlib.sha256(content).hexdigest(),
        mode,
        content,
    )


def _safe_relative_path(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or ":" in value
        or _UNSAFE_TEXT_RE.search(value)
    ):
        raise InstallError("payload path must be a safe relative POSIX path")
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or re.match(r"^[A-Za-z]:", value)
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise InstallError("payload path must be a safe relative POSIX path")
    for part in pure.parts:
        if part.endswith((" ", ".")) or part.split(".", 1)[0].upper() in _WINDOWS_RESERVED:
            raise InstallError("payload path is not portable to Windows")
    return pure.as_posix()


def _portable_path_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _is_self_payload_path(path: PurePosixPath) -> bool:
    if not path.parts:
        return False
    if path.as_posix() in _SELF_ROOT_FILES:
        return True
    if path.parts[0] not in _SELF_DIRECTORIES:
        return False
    if path.parts[0] == "scripts":
        return len(path.parts) == 2 and path.name in _SELF_SCRIPT_FILES
    if any(part in _BUILD_DIRECTORIES for part in path.parts):
        return False
    return not path.name.endswith(_BUILD_SUFFIXES)


def _has_link_component(root: Path, relative: PurePosixPath) -> bool:
    current = root
    for part in relative.parts:
        current = current / part
        if _is_link(current):
            return True
    return False


def _is_link(path: Path) -> bool:
    if path.is_symlink():
        return True
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


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise InstallError("invalid installer arguments")


def build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(description="Install the skill-auditor Agent Skill")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--skills-dir", type=Path, action="append", default=[])
    parser.add_argument("--write-payload-manifest", action="store_true")
    parser.add_argument("--check-payload-manifest", action="store_true")
    parser.add_argument("--include-untracked", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        if args.write_payload_manifest:
            destination = write_payload_manifest(
                args.source, include_untracked=args.include_untracked
            )
            print(f"Wrote {destination}")
            return 0
        if args.include_untracked:
            raise InstallError("--include-untracked is only valid when writing the manifest")
        entries = self_payload(args.source)
        if args.check_payload_manifest:
            print(f"Verified {args.source / PAYLOAD_MANIFEST}")
            return 0
        installed = install_snapshot(
            entries,
            "skill-auditor",
            targets=args.skills_dir or None,
        )
    except (InstallError, OSError) as exc:
        message = safe_display(exc).strip()
        print(f"install error: {message}", file=sys.stderr)
        return 3
    for destination in installed:
        print(f"Installed to {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
