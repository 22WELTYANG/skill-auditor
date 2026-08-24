"""Stable identities for content, rules, findings, and SARIF artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from . import manifest as manifest_mod
from .rules_loader import _STRING_KEYS

SCHEMA_VERSION = 1


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


def content_hash(
    target: Path,
    content_manifest: manifest_mod.ContentManifest | None = None,
) -> str:
    """Return the identity of the same immutable snapshot used by the scanner."""

    if content_manifest is not None:
        return content_manifest.digest
    return manifest_mod.build(
        target,
        archive_target=target.is_file(),
    ).digest


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
