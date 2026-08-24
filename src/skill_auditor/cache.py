"""Trusted local report cache keyed by all scan-affecting inputs."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path

SCHEMA = "skill-auditor-cache/v2"
LEGACY_SCHEMAS = {"skill-auditor-cache/v1"}


class CacheError(ValueError):
    pass


def default_directory() -> Path:
    configured = os.environ.get("SKILL_AUDITOR_CACHE_DIR")
    if configured:
        return Path(configured).expanduser()
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "skill-auditor" / "cache"
    return Path("~/.cache/skill-auditor").expanduser()


def key(payload: dict) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8", "surrogatepass")
    return hashlib.sha256(encoded).hexdigest()


def validate_directory(directory: Path, target: Path) -> Path:
    expanded = directory.expanduser()
    try:
        if expanded.exists() and expanded.is_symlink():
            raise CacheError("cache directory must not be a symlink")
        resolved = expanded.resolve(strict=False)
        physical = target.resolve(strict=True)
    except OSError as exc:
        raise CacheError(f"cannot resolve cache directory: {exc}") from exc
    if physical.is_dir():
        try:
            resolved.relative_to(physical)
        except ValueError:
            pass
        else:
            raise CacheError("cache directory must be outside the scanned target")
    return resolved


def load(directory: Path, cache_key: str) -> dict | None:
    path = directory / f"{cache_key}.json"
    try:
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file():
            raise CacheError("cache entry must be a regular file")
        data = json.loads(path.read_text(encoding="utf-8"))
    except CacheError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CacheError(f"cannot read cache entry: {exc}") from exc
    if isinstance(data, dict) and data.get("schema") in LEGACY_SCHEMAS:
        return None
    if (
        not isinstance(data, dict)
        or data.get("schema") != SCHEMA
        or data.get("cache_key") != cache_key
        or not isinstance(data.get("report"), dict)
    ):
        raise CacheError("cache entry failed integrity validation")
    report = data["report"]
    if (
        report.get("schema") != "skill-auditor-report/v1"
        or report.get("scan_status") != "COMPLETE"
        or not isinstance(report.get("source"), dict)
        or not isinstance(report.get("coverage"), dict)
    ):
        raise CacheError("cached report does not satisfy the report v1 contract")
    return report


def store(directory: Path, cache_key: str, report: dict) -> None:
    temporary: Path | None = None
    try:
        directory.mkdir(parents=True, exist_ok=True)
        if directory.is_symlink():
            raise CacheError("cache directory must not be a symlink")
        destination = directory / f"{cache_key}.json"
        temporary = directory / f".{cache_key}.{uuid.uuid4().hex}.tmp"
        payload = {
            "schema": SCHEMA,
            "cache_key": cache_key,
            "report": report,
        }
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.replace(temporary, destination)
    except CacheError:
        raise
    except OSError as exc:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        raise CacheError(f"cannot write cache entry: {exc}") from exc
