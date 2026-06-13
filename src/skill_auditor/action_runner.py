"""GitHub Composite Action orchestration without executing target content."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

from . import baseline, cli, formats, integrity
from .rules_loader import CRITICAL, INFO, load_rules

MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_BYTES = 1_000_000_000


class ActionError(ValueError):
    pass


def main() -> int:
    try:
        workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
        target = _workspace_path(workspace, os.environ.get("INPUT_PATH", "."))
        recursive = _boolean("INPUT_RECURSIVE", True)
        fail_on = cli._FAIL_ON[os.environ.get("INPUT_FAIL_ON", "critical").lower()]
        min_severity = cli._severity(os.environ.get("INPUT_MIN_SEVERITY", "info"))
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
    except (ActionError, cli.ScanError, ValueError, OSError) as exc:
        print(f"skill-auditor action error: {exc}", file=sys.stderr)
        _write_outputs({
            "verdict": "ERROR",
            "critical": 0,
            "warning": 0,
            "info": 0,
            "exit-code": 3,
            "sarif-file": "",
            "json-file": "",
            "content-hash": "",
        })
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
        data = baseline.build(report)
    except (cli.ScanError, FileNotFoundError) as exc:
        if (
            "found no valid SKILL.md roots" not in str(exc)
            and "does not exist" not in str(exc)
        ):
            raise
        data = {
            "schema": baseline.SCHEMA,
            "tool_version": None,
            "rules_digest": None,
            "content_hash": None,
            "fingerprints": {},
        }
    data["source"] = f"git:{trusted_ref}"
    return data


def _trusted_ref(event: dict) -> str:
    pull_request = event.get("pull_request")
    if isinstance(pull_request, dict):
        return str(pull_request.get("base", {}).get("sha") or "")
    return os.environ.get("GITHUB_SHA", "HEAD")


def _trusted_file(
    workspace: Path,
    ref: str,
    value: str,
    temporary: Path,
    name: str,
) -> Path | None:
    if not value:
        return None
    relative = PurePosixPath(value.replace("\\", "/"))
    if relative.is_absolute() or ".." in relative.parts:
        raise ActionError("trusted config/baseline path must be repository-relative")
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
            for member in members:
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts:
                    raise ActionError("base archive contains an unsafe path")
                if member.issym() or member.islnk() or member.isdev():
                    continue
                target = destination.joinpath(*path.parts)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    continue
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
    command = ["git", "archive", "--format=tar", ref]
    for attempt in range(2):
        with destination.open("wb") as output:
            result = subprocess.run(
                command, cwd=workspace, stdout=output, stderr=subprocess.PIPE
            )
        if result.returncode == 0:
            if destination.stat().st_size > MAX_ARCHIVE_BYTES:
                raise ActionError("base archive exceeds the archive size limit")
            return
        if attempt == 0:
            subprocess.run(
                ["git", "fetch", "--no-tags", "--depth=1", "origin", ref],
                cwd=workspace,
                capture_output=True,
                check=False,
            )
    message = result.stderr.decode("utf-8", "replace").strip()
    raise ActionError(message or "git archive failed")


def _git_output(workspace: Path, arguments: list[str]) -> bytes:
    command = ["git", *arguments]
    result = subprocess.run(command, cwd=workspace, capture_output=True)
    if result.returncode and arguments and arguments[0] in {"show", "archive"}:
        ref = arguments[-1].split(":", 1)[0]
        subprocess.run(
            ["git", "fetch", "--no-tags", "--depth=1", "origin", ref],
            cwd=workspace,
            capture_output=True,
            check=False,
        )
        result = subprocess.run(command, cwd=workspace, capture_output=True)
    if result.returncode:
        message = result.stderr.decode("utf-8", "replace").strip()
        raise ActionError(message or f"git {' '.join(arguments)} failed")
    return result.stdout


def _workspace_path(workspace: Path, value: str) -> Path:
    candidate = (workspace / value).resolve(strict=True)
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise ActionError("action path must remain inside GITHUB_WORKSPACE") from exc
    return candidate


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
    if value.lower() not in {"true", "false"}:
        raise ActionError(f"{name} must be true or false")
    return value.lower() == "true"


def _write_outputs(values: dict) -> None:
    destination = os.environ.get("GITHUB_OUTPUT")
    if not destination:
        return
    with Path(destination).open("a", encoding="utf-8", newline="\n") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


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
