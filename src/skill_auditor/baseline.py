"""Trusted baseline files and diff-aware finding classification."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

SCHEMA = "skill-auditor-baseline/v1"


class BaselineError(ValueError):
    pass


def build(report: dict) -> dict:
    if report.get("scan_status") != "COMPLETE":
        raise BaselineError("cannot build a baseline from an incomplete scan")
    counts = Counter(
        finding["fingerprint"]
        for finding in report.get("all_findings", report.get("findings", []))
        if not finding.get("semantic_resolved")
    )
    return {
        "schema": SCHEMA,
        "report_schema": report.get("schema"),
        "tool_version": report.get("version"),
        "scan_status": report.get("scan_status"),
        "rules_digest": report.get("rules_digest"),
        "content_hash": report.get("content_hash"),
        "source": report.get("source"),
        "coverage": report.get("coverage"),
        "semantic": report.get("semantic"),
        "fingerprints": dict(sorted(counts.items())),
    }


def validate_compatibility(
    data: dict | None,
    *,
    tool_version: str,
    rules_digest: str,
) -> None:
    """Reject a baseline created by a different scanner policy.

    A fingerprint match alone is insufficient: rule behavior may have changed
    while retaining the same rule id and source location.  Treat missing legacy
    metadata as incompatible instead of silently suppressing findings.
    """
    if data is None:
        return
    baseline_version = data.get("tool_version")
    baseline_digest = data.get("rules_digest")
    if not isinstance(baseline_version, str) or not baseline_version:
        raise BaselineError("baseline is missing tool_version")
    if not isinstance(baseline_digest, str) or not baseline_digest:
        raise BaselineError("baseline is missing rules_digest")
    if baseline_version != tool_version:
        raise BaselineError(
            "baseline tool version does not match the active scanner"
        )
    if baseline_digest != rules_digest:
        raise BaselineError(
            "baseline rules digest does not match the active policy"
        )
    if (
        data.get("report_schema") is not None
        and data.get("report_schema") != "skill-auditor-report/v1"
    ):
        raise BaselineError("baseline report schema is not supported")
    if data.get("scan_status") is not None and data.get("scan_status") != "COMPLETE":
        raise BaselineError("baseline does not describe a complete scan")


def load(path: str | Path) -> dict:
    candidate = Path(path).expanduser()
    try:
        if candidate.is_symlink() or not candidate.resolve(strict=True).is_file():
            raise BaselineError("baseline must be a regular file, not a symlink")
        data = json.loads(candidate.read_text(encoding="utf-8"))
    except BaselineError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BaselineError(f"cannot read baseline: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise BaselineError(f"unsupported baseline schema; expected {SCHEMA}")
    if not isinstance(data.get("tool_version"), str) or not data["tool_version"]:
        raise BaselineError("baseline tool_version must be a non-empty string")
    if not isinstance(data.get("rules_digest"), str) or not data["rules_digest"]:
        raise BaselineError("baseline rules_digest must be a non-empty string")
    if (
        data.get("report_schema") is not None
        and data.get("report_schema") != "skill-auditor-report/v1"
    ):
        raise BaselineError("baseline report_schema is not supported")
    if data.get("scan_status") is not None and data.get("scan_status") != "COMPLETE":
        raise BaselineError("baseline must describe a complete scan")
    for field in ("source", "coverage", "semantic"):
        if data.get(field) is not None and not isinstance(data[field], dict):
            raise BaselineError(f"baseline {field} must be an object")
    fingerprints = data.get("fingerprints")
    if not isinstance(fingerprints, dict):
        raise BaselineError("baseline fingerprints must be a mapping")
    clean = {}
    for fingerprint, count in fingerprints.items():
        if not isinstance(fingerprint, str) or not isinstance(count, int) or count < 0:
            raise BaselineError("baseline contains an invalid fingerprint count")
        clean[fingerprint] = count
    data["fingerprints"] = clean
    data["baseline_path"] = str(candidate.resolve(strict=True))
    return data


def classify(findings: list[dict], data: dict | None) -> None:
    remaining = Counter((data or {}).get("fingerprints", {}))
    for finding in findings:
        fingerprint = finding["fingerprint"]
        if remaining[fingerprint] > 0:
            finding["new"] = False
            remaining[fingerprint] -= 1
        else:
            finding["new"] = True
