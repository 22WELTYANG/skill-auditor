"""Trusted baseline files and diff-aware finding classification."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

SCHEMA = "skill-auditor-baseline/v1"


class BaselineError(ValueError):
    pass


def build(report: dict) -> dict:
    counts = Counter(
        finding["fingerprint"]
        for finding in report.get("all_findings", report.get("findings", []))
        if not finding.get("semantic_resolved")
    )
    return {
        "schema": SCHEMA,
        "tool_version": report.get("version"),
        "rules_digest": report.get("rules_digest"),
        "content_hash": report.get("content_hash"),
        "fingerprints": dict(sorted(counts.items())),
    }


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
    fingerprints = data.get("fingerprints")
    if not isinstance(fingerprints, dict):
        raise BaselineError("baseline fingerprints must be a mapping")
    clean = {}
    for fingerprint, count in fingerprints.items():
        if not isinstance(fingerprint, str) or not isinstance(count, int) or count < 0:
            raise BaselineError("baseline contains an invalid fingerprint count")
        clean[fingerprint] = count
    data["fingerprints"] = clean
    data["source"] = str(candidate.resolve(strict=True))
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
