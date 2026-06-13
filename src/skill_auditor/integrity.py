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
    semantic = report.get("semantic") or {}
    return {
        "schema": SCHEMA,
        "tool_version": report.get("version"),
        "content_hash": report.get("content_hash"),
        "rules_digest": report.get("rules_digest"),
        "semantic": {
            "mode": semantic.get("mode", "off"),
            "model": semantic.get("model"),
            "prompt_version": semantic.get("prompt_version"),
            "min_confidence": semantic.get("min_confidence"),
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
    return data


def differences(report: dict, lock: dict) -> list[str]:
    current = build(report)
    fields = (
        "tool_version",
        "content_hash",
        "rules_digest",
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
