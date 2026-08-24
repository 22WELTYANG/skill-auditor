"""GitHub Composite Action orchestration without executing target content."""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
from pathlib import Path, PurePosixPath

from . import baseline, cli, formats, identity, integrity
from .rules_loader import CRITICAL, INFO, load_rules
from .sanitize import safe_display

MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_BYTES = 1_000_000_000
GIT_TIMEOUT_SECONDS = 120
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_UNSAFE_PATH_RE = re.compile(
    r"[\x00-\x1f\x7f-\x9f\ud800-\udfff\u202a-\u202e\u2066-\u2069]"
)
_WINDOWS_RESERVED = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}
_ERROR_OUTPUTS = {
    "verdict": "ERROR",
    "critical": 0,
    "warning": 0,
    "info": 0,
    "exit-code": 3,
    "sarif-file": "",
    "json-file": "",
    "content-hash": "",
}


class ActionError(ValueError):
    pass


def main() -> int:
    # Establish a deterministic gate before doing work.  Later successful
    # values override these outputs; an unexpected crash still fails closed.
    if not _try_write_outputs(_ERROR_OUTPUTS):
        return 0
    try:
        workspace = Path(_required_env("GITHUB_WORKSPACE")).resolve(strict=True)
        target = _workspace_path(workspace, os.environ.get("INPUT_PATH", "."))
        recursive = _boolean("INPUT_RECURSIVE", True)
        fail_on_name = _choice("INPUT_FAIL_ON", "critical", cli._FAIL_ON)
        fail_on = cli._FAIL_ON[fail_on_name]
        min_severity_name = _choice(
            "INPUT_MIN_SEVERITY", "info", {"critical", "warning", "info"}
        )
        min_severity = cli._severity(min_severity_name)
        _boolean("INPUT_UPLOAD_SARIF", True)
        _boolean("INPUT_UPLOAD_REPORT", True)
        _label(
            "INPUT_ARTIFACT_NAME",
            os.environ.get("INPUT_ARTIFACT_NAME"),
            "skill-auditor-report",
        )
        _label(
            "INPUT_SARIF_CATEGORY",
            os.environ.get("INPUT_SARIF_CATEGORY"),
            "skill-auditor",
        )
        event = _event()
        trusted_ref = _trusted_ref(event)
        temporary = Path(tempfile.mkdtemp(
            prefix="skill-auditor-action-",
            dir=os.environ.get("RUNNER_TEMP"),
        ))
        try:
            config_path = _trusted_file(
                workspace,
                trusted_ref,
                os.environ.get("INPUT_CONFIG", ""),
                temporary,
                "trusted-config.yml",
            )
            baseline_data = _action_baseline(
                workspace,
                trusted_ref,
                os.environ.get("INPUT_BASELINE", "auto"),
                os.environ.get("INPUT_PATH", "."),
                recursive,
                config_path,
                temporary,
                fail_on,
                min_severity,
            )
            rules = load_rules()
            if recursive:
                report = cli.build_recursive_report(
                    str(target),
                    target,
                    rules,
                    min_severity=min_severity,
                    fail_on=fail_on,
                    config_path=config_path,
                    source_root=workspace,
                    baseline_data=baseline_data,
                    use_cache=False,
                )
            else:
                resolved = cli.resolve_target(str(target))
                report = cli.build_report(
                    str(target),
                    resolved.path,
                    rules,
                    min_severity=min_severity,
                    fail_on=fail_on,
                    config_path=config_path,
                    archive_target=resolved.archive,
                    source_root=workspace,
                    baseline_data=baseline_data,
                )
            json_path = temporary / "skill-auditor.json"
            sarif_path = temporary / "skill-auditor.sarif"
            integrity.write(json_path, report)
            sarif_path.write_text(
                formats.render_sarif(report, rules) + "\n",
                encoding="utf-8",
            )
            _write_summary(report)
            summary = report["gate_summary"]
            outputs = {
                "verdict": report["verdict"],
                "critical": summary[CRITICAL],
                "warning": summary["WARNING"],
                "info": summary[INFO],
                "exit-code": report["exit_code"],
                "sarif-file": str(sarif_path),
                "json-file": str(json_path),
                "content-hash": report["content_hash"],
            }
            _write_outputs(outputs)
            return 0
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
    except Exception as exc:
        print(f"skill-auditor action error: {safe_display(exc)}", file=sys.stderr)
        _try_write_outputs(_ERROR_OUTPUTS)
        return 0


def _action_baseline(
    workspace: Path,
    trusted_ref: str,
    value: str,
    target_value: str,
    recursive: bool,
    config_path: Path | None,
    temporary: Path,
    fail_on: str,
    min_severity: str,
) -> dict | None:
    normalized = (value or "auto").strip()
    if normalized.lower() == "none":
        return None
    if normalized.lower() != "auto":
        path = _trusted_file(
            workspace, trusted_ref, normalized, temporary, "trusted-baseline.json"
        )
        return baseline.load(path) if path else None
    event = _event()
    if "pull_request" not in event:
        return None
    base_root = temporary / "base"
    _extract_git_archive(workspace, trusted_ref, base_root)
    rules = load_rules()
    try:
        base_target = _workspace_path(base_root, target_value)
    except FileNotFoundError:
        data = _empty_baseline(rules)
    else:
        try:
            if recursive:
                report = cli.build_recursive_report(
                    trusted_ref,
                    base_target,
                    rules,
                    min_severity=min_severity,
                    fail_on=fail_on,
                    config_path=config_path,
                    source_root=base_root,
                    use_cache=False,
                )
            else:
                resolved = cli.resolve_target(str(base_target))
                report = cli.build_report(
                    trusted_ref,
                    resolved.path,
                    rules,
                    min_severity=min_severity,
                    fail_on=fail_on,
                    config_path=config_path,
                    archive_target=resolved.archive,
                    source_root=base_root,
                )
            if report.get("scan_status") != "COMPLETE":
                raise ActionError("the trusted base scan is incomplete")
            data = baseline.build(report)
        except cli.ScanError as exc:
            if (
                "found no valid SKILL.md roots" not in str(exc)
                and "does not exist" not in str(exc)
            ):
                raise
            data = _empty_baseline(rules)
    data["baseline_path"] = f"git:{trusted_ref}"
    return data


def _empty_baseline(rules: list[dict]) -> dict:
    return {
        "schema": baseline.SCHEMA,
        "report_schema": "skill-auditor-report/v1",
        "tool_version": cli.VERSION,
        "scan_status": "COMPLETE",
        "rules_digest": identity.rules_digest(rules),
        "content_hash": None,
        "fingerprints": {},
    }


def _trusted_ref(event: dict) -> str:
    pull_request = event.get("pull_request")
    if isinstance(pull_request, dict):
        value = str(pull_request.get("base", {}).get("sha") or "")
    else:
        value = os.environ.get("GITHUB_SHA", "")
    normalized = value.lower()
    if not _COMMIT_RE.fullmatch(normalized):
        raise ActionError("trusted base ref must be a full commit SHA")
    return normalized


def _trusted_file(
    workspace: Path,
    ref: str,
    value: str,
    temporary: Path,
    name: str,
) -> Path | None:
    if not value:
        return None
    relative = _trusted_relative_path(value)
    content = _git_output(workspace, ["show", f"{ref}:{relative.as_posix()}"])
    destination = temporary / name
    destination.write_bytes(content)
    return destination


def _extract_git_archive(workspace: Path, ref: str, destination: Path) -> None:
    destination.mkdir(parents=True)
    archive_path = destination.parent / "base.tar"
    _git_archive(workspace, ref, archive_path)
    total = 0
    try:
        with tarfile.open(archive_path, mode="r:") as handle:
            members = handle.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise ActionError("base archive contains too many members")
            seen_members: set[str] = set()
            canonical_paths: dict[str, str] = {}
            regular_files: set[str] = set()
            for member in members:
                member_name = (
                    member.name[:-1]
                    if member.isdir() and member.name.endswith("/")
                    else member.name
                )
                path = _trusted_relative_path(member_name)
                portable = path.as_posix()
                key = _portable_path_key(portable)
                if key in seen_members:
                    raise ActionError("base archive contains colliding paths")
                prefixes = [
                    PurePosixPath(*path.parts[:index]).as_posix()
                    for index in range(1, len(path.parts) + 1)
                ]
                for prefix in prefixes:
                    prefix_key = _portable_path_key(prefix)
                    existing = canonical_paths.get(prefix_key)
                    if existing is not None and existing != prefix:
                        raise ActionError("base archive contains colliding paths")
                for prefix in prefixes[:-1]:
                    parent_key = _portable_path_key(prefix)
                    if parent_key in regular_files:
                        raise ActionError("base archive contains a file/directory conflict")
                if member.isfile() and any(
                    existing.startswith(key + "/") for existing in canonical_paths
                ):
                    raise ActionError("base archive contains a file/directory conflict")
                if not member.isdir() and not member.isfile():
                    raise ActionError("base archive contains a special entry")
                if member.size < 0:
                    raise ActionError("base archive contains an invalid file size")
                seen_members.add(key)
                for prefix in prefixes:
                    canonical_paths.setdefault(_portable_path_key(prefix), prefix)
                target = destination.joinpath(*path.parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                regular_files.add(key)
                total += member.size
                if total > MAX_ARCHIVE_BYTES:
                    raise ActionError("base archive exceeds the extraction limit")
                source = handle.extractfile(member)
                if source is None:
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("wb") as output:
                    shutil.copyfileobj(source, output)
    finally:
        archive_path.unlink(missing_ok=True)


def _git_archive(workspace: Path, ref: str, destination: Path) -> None:
    arguments = ["archive", "--format=tar", ref]
    for attempt in range(2):
        with destination.open("wb") as output:
            result = _run_git(
                arguments,
                workspace,
                stdout=output,
                stderr=subprocess.PIPE,
            )
        if result.returncode == 0:
            if destination.stat().st_size > MAX_ARCHIVE_BYTES:
                raise ActionError("base archive exceeds the archive size limit")
            return
        if attempt == 0:
            _run_git(
                ["fetch", "--no-tags", "--depth=1", "origin", ref],
                workspace,
                capture_output=True,
            )
    raise ActionError("cannot read the trusted base commit")


def _git_output(workspace: Path, arguments: list[str]) -> bytes:
    result = _run_git(arguments, workspace, capture_output=True)
    if result.returncode and arguments and arguments[0] in {"show", "archive"}:
        ref = arguments[-1].split(":", 1)[0]
        _run_git(
            ["fetch", "--no-tags", "--depth=1", "origin", ref],
            workspace,
            capture_output=True,
        )
        result = _run_git(arguments, workspace, capture_output=True)
    if result.returncode:
        raise ActionError("cannot read trusted repository content")
    return result.stdout


def _run_git(arguments: list[str], workspace: Path, **kwargs):
    command = [
        "git",
        "-c",
        "credential.helper=",
        "-c",
        f"core.hooksPath={os.devnull}",
        *arguments,
    ]
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_TERMINAL_PROMPT": "0",
            "GCM_INTERACTIVE": "Never",
            "GIT_SSH_COMMAND": "ssh -oBatchMode=yes",
        }
    )
    try:
        return subprocess.run(
            command,
            cwd=workspace,
            env=environment,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
            **kwargs,
        )
    except subprocess.TimeoutExpired as exc:
        raise ActionError("trusted Git operation timed out") from exc


def _trusted_relative_path(value: str) -> PurePosixPath:
    if (
        not value
        or "\\" in value
        or ":" in value
        or _UNSAFE_PATH_RE.search(value)
    ):
        raise ActionError("trusted config/baseline path must be a safe POSIX path")
    raw_parts = value.split("/")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or any(part in {"", ".", ".."} for part in raw_parts)
    ):
        raise ActionError("trusted config/baseline path must be repository-relative")
    for part in relative.parts:
        if part.endswith((" ", ".")) or part.split(".", 1)[0].upper() in _WINDOWS_RESERVED:
            raise ActionError("trusted config/baseline path is not portable to Windows")
    return relative


def _portable_path_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def _workspace_path(workspace: Path, value: str) -> Path:
    candidate = Path(os.path.abspath(workspace / value))
    try:
        relative = candidate.relative_to(workspace)
    except ValueError as exc:
        raise ActionError("action path must remain inside GITHUB_WORKSPACE") from exc
    current = workspace
    for part in relative.parts:
        current = current / part
        try:
            current.lstat()
            if current.is_symlink() or _is_junction(current):
                raise ActionError("action path must not traverse a link or junction")
        except ActionError:
            raise
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise ActionError("action path cannot be inspected safely") from exc
    return candidate


def _is_junction(path: Path) -> bool:
    checker = getattr(path, "is_junction", None)
    if checker is not None:
        try:
            return bool(checker())
        except OSError as exc:
            raise ActionError("action path junction status cannot be inspected") from exc
    try:
        attributes = path.lstat().st_file_attributes  # type: ignore[attr-defined]
        return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except AttributeError:
        return False
    except OSError as exc:
        raise ActionError("action path junction status cannot be inspected") from exc


def _event() -> dict:
    path = os.environ.get("GITHUB_EVENT_PATH")
    if not path:
        return {}
    try:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ActionError(f"cannot read GitHub event: {exc}") from exc


def _boolean(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    if value not in {"true", "false"}:
        raise ActionError(f"{name} must be true or false")
    return value == "true"


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ActionError(f"{name} is required")
    return value


def _choice(name: str, default: str, choices) -> str:
    value = (os.environ.get(name) or default).lower()
    if value not in choices:
        expected = ", ".join(sorted(choices))
        raise ActionError(f"{name} must be one of: {expected}")
    return value


def _label(name: str, value: str | None, default: str) -> str:
    normalized = value if value is not None else default
    if not _LABEL_RE.fullmatch(normalized):
        raise ActionError(
            f"{name} must contain 1-128 letters, digits, dots, underscores, or hyphens"
        )
    return normalized


def _write_outputs(values: dict) -> None:
    destination = os.environ.get("GITHUB_OUTPUT")
    if not destination:
        return
    with Path(destination).open("a", encoding="utf-8", newline="\n") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def _try_write_outputs(values: dict) -> bool:
    try:
        _write_outputs(values)
        return True
    except Exception:
        print("skill-auditor action error: cannot write Action outputs", file=sys.stderr)
        return False


def _write_summary(report: dict) -> None:
    destination = os.environ.get("GITHUB_STEP_SUMMARY")
    if not destination:
        return
    summary = report["gate_summary"]
    lines = [
        "## skill-auditor",
        "",
        f"**Verdict:** `{report['verdict']}`",
        "",
        "| CRITICAL | WARNING | INFO |",
        "|---:|---:|---:|",
        f"| {summary['CRITICAL']} | {summary['WARNING']} | {summary['INFO']} |",
        "",
        f"Content hash: `{report['content_hash']}`",
    ]
    Path(destination).write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
