"""Local and remote scan-target resolution without a Git working checkout."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unicodedata
import urllib.parse
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from . import archives
from .manifest import safe_display

MAX_REMOTE_ARCHIVE_BYTES = 100_000_000
MAX_REMOTE_MEMBERS = 10_000
_UNSAFE_TEXT_RE = re.compile(
    r"[\x00-\x1f\x7f-\x9f\ud800-\udfff\u202a-\u202e\u2066-\u2069]"
)
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


class TargetError(ValueError):
    pass


@dataclass(frozen=True)
class ResolvedTarget:
    path: Path
    temporary: Path | None = None
    archive: bool = False
    source: dict | None = None
    display_target: str | None = None


def resolve(target: str, ref: str | None = None) -> ResolvedTarget:
    if _is_remote_target(target):
        return _resolve_remote_target(target, ref)
    if ref is not None:
        raise TargetError("--ref is only valid for a remote Git target")
    candidate = Path(target).expanduser()
    try:
        if not candidate.exists():
            raise TargetError(f"path does not exist: {safe_display(target)}")
        if candidate.is_symlink() or _is_junction(candidate):
            raise TargetError("target root must not be a symlink or junction")
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise TargetError(f"cannot resolve target: {safe_display(str(exc))}") from exc
    if resolved.is_file() and archives.is_archive(resolved):
        return ResolvedTarget(
            resolved,
            archive=True,
            source={"kind": "archive", "path": str(resolved)},
            display_target=str(resolved),
        )
    if not resolved.is_dir():
        raise TargetError("target must be a skill directory or supported archive")
    return ResolvedTarget(
        resolved,
        source={"kind": "local", "path": str(resolved)},
        display_target=str(resolved),
    )


def _is_remote_target(target: str) -> bool:
    return bool(re.match(r"^(?:https?|ssh|file)://|^git@", target)) or target.startswith("github.com/")


def _resolve_remote_target(target: str, ref: str | None) -> ResolvedTarget:
    url = target if not target.startswith("github.com/") else "https://" + target
    normalized = _normalized_repository(url)
    requested_ref = _validated_ref(ref or "HEAD")
    temporary = Path(tempfile.mkdtemp(prefix="skill-auditor-"))
    bare = temporary / "repository.git"
    archive_path = temporary / "snapshot.tar"
    destination = temporary / "snapshot"
    try:
        _run_git(["init", "--bare", str(bare)], "cannot initialize remote snapshot")
        _run_git(
            ["-C", str(bare), "remote", "add", "origin", url],
            "cannot configure remote snapshot",
        )
        _run_git(
            ["-C", str(bare), "fetch", "--depth", "1", "--no-tags", "--", "origin", requested_ref],
            "cannot fetch the requested remote ref",
            timeout=120,
        )
        commit = _run_git(
            ["-C", str(bare), "rev-parse", "--verify", "FETCH_HEAD^{commit}"],
            "cannot resolve the requested remote ref",
            text_output=True,
        ).strip().lower()
        if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
            raise TargetError("Git returned an invalid resolved commit")
        with archive_path.open("wb") as output:
            _run_git(
                ["-C", str(bare), "archive", "--format=tar", commit],
                "cannot materialize the resolved remote commit",
                stdout=output,
                timeout=120,
            )
        if archive_path.stat().st_size > MAX_REMOTE_ARCHIVE_BYTES:
            raise TargetError("remote snapshot exceeds the materialization limit")
        _extract_remote_archive(archive_path, destination)
    except (OSError, TargetError) as exc:
        shutil.rmtree(temporary, ignore_errors=True)
        if isinstance(exc, TargetError):
            raise
        raise TargetError(f"cannot materialize remote target: {safe_display(str(exc))}") from exc
    return ResolvedTarget(
        destination,
        temporary,
        False,
        {
            "kind": "git",
            "repository": normalized,
            "requested_ref": requested_ref,
            "resolved_commit": commit,
        },
        normalized,
    )


def _run_git(
    arguments: list[str],
    failure: str,
    *,
    text_output: bool = False,
    stdout=None,
    timeout: float = 15,
) -> str:
    environment = os.environ.copy()
    environment.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "Never",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_SSH_COMMAND": "ssh -oBatchMode=yes",
    })
    try:
        result = subprocess.run(
            [
                "git",
                "-c", "credential.helper=",
                "-c", f"core.hooksPath={os.devnull}",
                *arguments,
            ],
            check=False,
            stdout=(subprocess.PIPE if stdout is None else stdout),
            stderr=subprocess.PIPE,
            text=text_output,
            timeout=timeout,
            env=environment,
        )
    except FileNotFoundError as exc:
        raise TargetError("git is required for a remote target") from exc
    except subprocess.TimeoutExpired as exc:
        raise TargetError(failure + " (timed out)") from exc
    except OSError as exc:
        raise TargetError(failure) from exc
    if result.returncode:
        raise TargetError(failure)
    if stdout is not None:
        return ""
    output = result.stdout
    if isinstance(output, bytes):
        try:
            return output.decode("utf-8")
        except UnicodeError as exc:
            raise TargetError("git returned non-UTF-8 metadata") from exc
    return output or ""


def _normalized_repository(url: str) -> str:
    if _UNSAFE_TEXT_RE.search(url):
        raise TargetError("remote repository contains unsupported characters")
    if url.startswith("git@"):
        match = re.fullmatch(r"git@([A-Za-z0-9.-]+):([^\\?#\s]+)", url)
        if not match:
            raise TargetError("scp-style Git URL contains unsupported characters")
        return f"git@{match.group(1).lower()}:{match.group(2)}"
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https", "ssh", "file"}:
        raise TargetError("remote repository must use HTTPS, SSH, or file URL syntax")
    if parsed.query or parsed.fragment:
        raise TargetError("remote repository URL must not contain a query or fragment")
    if parsed.scheme != "file" and not parsed.hostname:
        raise TargetError("remote repository URL is missing a host")
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError as exc:
        raise TargetError("remote repository URL contains an invalid port") from exc
    if port:
        host += f":{port}"
    return urllib.parse.urlunsplit((parsed.scheme.lower(), host.lower(), parsed.path, "", ""))


def _validated_ref(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", value):
        raise TargetError("remote ref contains unsupported characters")
    if ".." in value or "//" in value or value.endswith(("/", ".", ".lock")):
        raise TargetError("remote ref is not a safe branch, tag, or commit name")
    return value


def _extract_remote_archive(archive_path: Path, destination: Path) -> None:
    destination.mkdir()
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            members = archive.getmembers()
            if len(members) > MAX_REMOTE_MEMBERS:
                raise TargetError("remote snapshot contains too many entries")
            total = 0
            seen: set[str] = set()
            validated: list[tuple[tarfile.TarInfo, PurePosixPath]] = []
            for member in members:
                original_name = member.name
                name = original_name.replace("\\", "/")
                path = PurePosixPath(name)
                canonical = path.as_posix()
                comparable = (
                    name[:-1] if member.isdir() and name.endswith("/") else name
                )
                key = unicodedata.normalize("NFC", canonical).casefold()
                if (
                    not name
                    or "\\" in original_name
                    or comparable != canonical
                    or path.is_absolute()
                    or ".." in path.parts
                    or _looks_windows_absolute(name)
                    or _UNSAFE_TEXT_RE.search(name)
                    or any(_unsafe_windows_component(part) for part in path.parts)
                    or member.size < 0
                    or key in seen
                ):
                    raise TargetError("remote snapshot contains an unsafe or duplicate path")
                seen.add(key)
                if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                    raise TargetError("remote snapshot contains a link or special file")
                total += member.size
                if total > MAX_REMOTE_ARCHIVE_BYTES:
                    raise TargetError("remote snapshot exceeds the expanded size limit")
                validated.append((member, path))
            for member, normalized_path in validated:
                output_path = destination.joinpath(*normalized_path.parts)
                if member.isdir():
                    output_path.mkdir(parents=True, exist_ok=True)
                    continue
                source = archive.extractfile(member)
                if source is None:
                    raise TargetError("remote snapshot contains an unreadable file")
                output_path.parent.mkdir(parents=True, exist_ok=True)
                data = source.read()
                if len(data) != member.size:
                    raise TargetError("remote snapshot file is truncated")
                output_path.write_bytes(data)
                try:
                    output_path.chmod(member.mode & 0o777)
                except OSError:
                    pass
    except TargetError:
        raise
    except (OSError, tarfile.TarError, EOFError) as exc:
        raise TargetError("cannot inspect the remote Git archive") from exc


def _looks_windows_absolute(name: str) -> bool:
    return len(name) >= 3 and name[1] == ":" and name[2] in "/\\"


def _unsafe_windows_component(component: str) -> bool:
    if not component or ":" in component or component.endswith((" ", ".")):
        return True
    return component.split(".", 1)[0].upper() in _WINDOWS_RESERVED


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
