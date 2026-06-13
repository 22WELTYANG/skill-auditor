"""Stable identities for content, rules, findings, and SARIF artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from .rules_loader import _STRING_KEYS

SCHEMA_VERSION = 1
_EXCLUDED_NAMES = {
    ".git",
    ".pytest_cache",
    ".skill-auditor-cache",
    "__pycache__",
    "skill-auditor.lock",
}
_EXCLUDED_SUFFIXES = {".pyc", ".pyo"}
_GENERATED_REPORTS = {
    "skill-auditor.json",
    "skill-auditor.sarif",
    "skill-auditor.md",
}


def rules_digest(rules: list[dict]) -> str:
    payload = [
        {key: str(rule.get(key) or "") for key in _STRING_KEYS}
        for rule in sorted(rules, key=lambda item: item["id"])
    ]
    return _sha256(_json_bytes(payload))


def finding_fingerprint(finding: dict) -> str:
    payload = {
        "schema": SCHEMA_VERSION,
        "rule_id": finding["rule_id"],
        "file": _portable(finding.get("artifact_uri") or finding["file"]),
        "archive_member": finding.get("archive_member"),
        "snippet": _normalize_evidence(finding.get("snippet", "")),
    }
    return _sha256(_json_bytes(payload))


def enrich_findings(findings: list[dict], root: Path, source_root: Path | None) -> None:
    for finding in findings:
        artifact_uri, archive_member = artifact_location(
            root, source_root, finding["file"]
        )
        finding["artifact_uri"] = artifact_uri
        finding["archive_member"] = archive_member
        finding["fingerprint"] = finding_fingerprint(finding)


def artifact_location(
    root: Path,
    source_root: Path | None,
    finding_file: str,
) -> tuple[str, str | None]:
    physical_name, separator, member = finding_file.partition("!")
    physical = root if root.is_file() else root / Path(physical_name)
    base = source_root or (root.parent if root.is_file() else root)
    try:
        uri = physical.resolve(strict=False).relative_to(
            base.resolve(strict=True)
        )
    except (OSError, ValueError):
        uri = Path(physical.name if root.is_file() else physical_name)
    return _portable(uri), member if separator else None


def content_hash(target: Path) -> str:
    digest = hashlib.sha256()
    digest.update(f"skill-auditor-content-v{SCHEMA_VERSION}\0".encode())
    if target.is_file():
        _hash_file(digest, target, target.name)
        return digest.hexdigest()

    root = target.resolve(strict=True)

    def walk(directory: Path) -> None:
        entries = sorted(os.scandir(directory), key=lambda item: item.name)
        for entry in entries:
            path = Path(entry.path)
            relative = _portable(path.relative_to(root))
            if _excluded(path.name):
                continue
            if entry.is_symlink():
                digest.update(b"L\0")
                digest.update(relative.encode("utf-8", "surrogatepass"))
                digest.update(b"\0")
                try:
                    digest.update(os.readlink(path).encode("utf-8", "surrogatepass"))
                except OSError as exc:
                    digest.update(str(exc).encode("utf-8", "replace"))
                digest.update(b"\0")
            elif entry.is_dir(follow_symlinks=False):
                digest.update(b"D\0")
                digest.update(relative.encode("utf-8", "surrogatepass"))
                digest.update(b"\0")
                walk(path)
            elif entry.is_file(follow_symlinks=False):
                _hash_file(digest, path, relative)
            else:
                digest.update(b"O\0")
                digest.update(relative.encode("utf-8", "surrogatepass"))
                digest.update(b"\0")

    walk(root)
    return digest.hexdigest()


def report_digest(report: dict) -> str:
    payload = {
        "content_hash": report.get("content_hash"),
        "rules_digest": report.get("rules_digest"),
        "verdict": report.get("verdict"),
        "findings": [
            {
                "fingerprint": item.get("fingerprint"),
                "severity": item.get("severity"),
                "new": item.get("new"),
                "semantic_resolved": item.get("semantic_resolved", False),
            }
            for item in report.get("all_findings", report.get("findings", []))
        ],
    }
    return _sha256(_json_bytes(payload))


def aggregate_content_hash(reports: list[dict]) -> str:
    payload = [
        {
            "target": report.get("target"),
            "content_hash": report.get("content_hash"),
        }
        for report in sorted(reports, key=lambda item: str(item.get("target", "")))
    ]
    return _sha256(_json_bytes(payload))


def _hash_file(digest, path: Path, relative: str) -> None:
    digest.update(b"F\0")
    digest.update(_portable(relative).encode("utf-8", "surrogatepass"))
    digest.update(b"\0")
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    digest.update(b"\0")


def _excluded(name: str) -> bool:
    return (
        name in _EXCLUDED_NAMES
        or name in _GENERATED_REPORTS
        or Path(name).suffix.lower() in _EXCLUDED_SUFFIXES
    )


def _normalize_evidence(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _portable(value: str | Path) -> str:
    return str(value).replace("\\", "/")


def _json_bytes(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
