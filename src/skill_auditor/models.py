"""Typed scanner contracts used at the CLI/module boundaries."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ScanOptions:
    min_severity: str
    fail_on: str
    archive_target: bool = False
    source_root: str | Path | None = None

    def cache_policy(self) -> dict:
        return {
            "min_severity": self.min_severity,
            "fail_on": self.fail_on,
            "archive_target": self.archive_target,
        }


@dataclass(frozen=True)
class Finding:
    rule_id: str
    category: str
    severity: str
    layer: str
    file: str
    line: int
    snippet: str
    rationale: str = ""
    guidance: str = ""
    needs_semantic_review: bool = False
    confidence: str = "high"
    context: list[str] | None = None

    def as_dict(self) -> dict:
        recommendation = self.guidance or "Review this finding before trusting the skill."
        return {
            "rule_id": self.rule_id,
            "layer": self.layer,
            "rationale": self.rationale,
            "guidance": self.guidance,
            "needs_semantic_review": self.needs_semantic_review,
            "confidence": self.confidence,
            "suppressed": False,
            "suppressed_reason": None,
            "context": self.context if self.needs_semantic_review else None,
            "id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "explanation": self.rationale,
            "recommendation": recommendation,
        }


@dataclass(frozen=True)
class ScanReport:
    schema: str
    scan_status: str
    source: dict
    coverage: dict
    data: dict[str, Any] = field(repr=False)

    @classmethod
    def from_dict(cls, data: dict) -> "ScanReport":
        status = data.get("scan_status")
        if status not in {"COMPLETE", "INCOMPLETE"}:
            raise ValueError("scan report has an invalid scan_status")
        source = data.get("source")
        coverage = data.get("coverage")
        if not isinstance(source, dict) or not isinstance(coverage, dict):
            raise ValueError("scan report is missing source or coverage metadata")
        return cls(
            schema=str(data.get("schema", "")),
            scan_status=status,
            source=dict(source),
            coverage=dict(coverage),
            data=dict(data),
        )

    def as_dict(self) -> dict:
        output = dict(self.data)
        output.update({
            "schema": self.schema,
            "scan_status": self.scan_status,
            "source": dict(self.source),
            "coverage": dict(self.coverage),
        })
        return output
