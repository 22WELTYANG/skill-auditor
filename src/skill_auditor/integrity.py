"""Audit lockfiles for content and scanner policy pinning."""

from __future__ import annotations

import json
import os
from pathlib import Path

from . import identity

SCHEMA = "skill-auditor-lock/v1"


class LockError(ValueError):
    pass


def build(report: dict) -> dict:
    if report.get("scan_status") != "COMPLETE":
        raise LockError("cannot build a lock from an incomplete scan")
    semantic = report.get("semantic") or {}
    baseline = report.get("baseline") or {}
    source = report.get("source") or {}
    return {
        "schema": SCHEMA,
        "report_schema": report.get("schema"),
        "tool_version": report.get("version"),
        "scan_status": report.get("scan_status"),
        "content_hash": report.get("content_hash"),
        "rules_digest": report.get("rules_digest"),
        "coverage": report.get("coverage"),
        "source": {
            "kind": source.get("kind"),
            "repository": source.get("repository"),
            "requested_ref": source.get("requested_ref"),
            "resolved_commit": source.get("resolved_commit"),
            "content_hash": source.get("content_hash") or report.get("content_hash"),
        },
        "policy": {
            "fail_on": report.get("fail_on"),
            "min_severity": report.get("min_severity"),
            "config_digest": report.get("config_digest"),
            "baseline_tool_version": baseline.get("tool_version"),
            "baseline_rules_digest": baseline.get("rules_digest"),
        },
        "semantic": {
            "mode": semantic.get("mode", "off"),
            "model": semantic.get("model"),
            "base_url": semantic.get("base_url"),
            "prompt_version": semantic.get("prompt_version"),
            "min_confidence": semantic.get("min_confidence"),
            "effect": semantic.get("effect", "advisory"),
        },
        "verdict": report.get("verdict"),
        "full_verdict": report.get("full_verdict"),
        "report_digest": identity.report_digest(report),
    }


def load(path: str | Path) -> dict:
    candidate = Path(path).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
        if candidate.is_symlink() or not resolved.is_file():
            raise LockError("lockfile must be a regular file, not a symlink")
        data = json.loads(resolved.read_text(encoding="utf-8"))
    except LockError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LockError(f"cannot read lockfile: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise LockError(f"unsupported lock schema; expected {SCHEMA}")
    for field in ("tool_version", "content_hash", "rules_digest", "report_digest"):
        if not isinstance(data.get(field), str) or not data[field]:
            raise LockError(f"lockfile {field} must be a non-empty string")
    if data.get("report_schema") != "skill-auditor-report/v1":
        raise LockError("lockfile report schema is not supported")
    if data.get("scan_status") != "COMPLETE":
        raise LockError("lockfile must describe a complete scan")
    for field in ("coverage", "source", "policy", "semantic"):
        if not isinstance(data.get(field), dict):
            raise LockError(f"lockfile {field} must be an object")
    return data


def differences(report: dict, lock: dict) -> list[str]:
    current = build(report)
    fields = (
        "report_schema",
        "tool_version",
        "scan_status",
        "content_hash",
        "rules_digest",
        "coverage",
        "source",
        "policy",
        "semantic",
        "verdict",
        "full_verdict",
        "report_digest",
    )
    return [field for field in fields if current.get(field) != lock.get(field)]


def write(path: str | Path, payload: dict) -> None:
    destination = Path(path).expanduser()
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(
            f".{destination.name}.{os.getpid()}.tmp"
        )
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.replace(temporary, destination)
    except OSError as exc:
        raise LockError(f"cannot write JSON file: {exc}") from exc
