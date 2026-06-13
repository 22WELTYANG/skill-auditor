"""Report renderers."""

from __future__ import annotations

import json
import sys

from .rules_loader import CRITICAL, INFO, WARNING

VERDICT_EMOJI = {
    "DO_NOT_INSTALL": "⛔",
    "REVIEW_BEFORE_INSTALL": "⚠️",
    "SAFE_TO_INSTALL": "✅",
}
_SARIF_LEVEL = {CRITICAL: "error", WARNING: "warning", INFO: "note"}


def render_pretty(report: dict, *, color: bool | None = None, verbose: bool = False) -> str:
    color = sys.stdout.isatty() if color is None else color

    def styled(code: str, value: str) -> str:
        return f"\033[{code}m{value}\033[0m" if color else value

    severity_color = {CRITICAL: "1;31", WARNING: "1;33", INFO: "1;36"}
    summary = report["summary"]
    output = [
        "=" * 64,
        f" skill-auditor v{report['version']} - scan report",
        f" target : {report['target']}",
        f" files  : {len(report['scanned_files'])} scanned   rules: {report['rules_loaded']}",
        f" totals : {styled('1;31', str(summary[CRITICAL]) + ' CRITICAL')}  "
        f"{styled('1;33', str(summary[WARNING]) + ' WARNING')}  "
        f"{styled('1;36', str(summary[INFO]) + ' INFO')}   "
        f"({summary['needs_semantic_review']} need semantic review"
        f"{', ' + str(summary['suppressed']) + ' suppressed' if summary.get('suppressed') else ''})",
        "=" * 64,
    ]
    for finding in report["findings"]:
        output.append(_pretty_finding(finding, styled, severity_color))
    if not report["findings"]:
        output += ["", "  No findings at the selected display threshold.", ""]
    if report.get("scan_diagnostics"):
        output += ["", " Scan diagnostics:"]
        output += [f"  - {item['path']}: {item['message']}"
                   for item in report["scan_diagnostics"]]
    if verbose and report.get("suppressed"):
        output += ["", "-" * 64, " suppressed by trusted config", "-" * 64]
        for finding in report["suppressed"]:
            output.append(_pretty_finding(finding, styled, severity_color, suppressed=True))
    output += [
        "",
        "=" * 64,
        f" VERDICT: {VERDICT_EMOJI.get(report['verdict'], '')} {report['verdict_label']}"
        f"   (fail-on: {report['fail_on']})",
        "=" * 64,
    ]
    return "\n".join(output)


def _pretty_finding(finding, styled, severity_color, *, suppressed=False) -> str:
    tag = styled(severity_color.get(finding["severity"], "0"), f"[{finding['severity']}]")
    semantic = "  ~semantic" if finding["needs_semantic_review"] else ""
    suppression = "  [suppressed]" if suppressed else ""
    lines = [
        f"\n{tag} {finding['category']}  ({finding['rule_id']}){semantic}"
        f"  conf={finding.get('confidence', 'high')}{suppression}",
        f"  {finding.get('artifact_uri') or finding['file']}:{finding['line']}",
        f"    > {finding['snippet']}",
        f"    why: {finding['rationale']}",
    ]
    if suppressed:
        lines.append(f"    suppressed: {finding.get('suppressed_reason', '')}")
    if finding["needs_semantic_review"] and finding.get("guidance"):
        lines.append(f"    review: {finding['guidance']}")
    return "\n".join(lines)


def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)


def render_markdown(report: dict) -> str:
    summary = report["summary"]
    output = [
        f"## {VERDICT_EMOJI.get(report['verdict'], '')} skill-auditor — {report['verdict_label']}",
        "",
        f"**Target:** `{report['target']}`  ",
        f"**Files scanned:** {len(report['scanned_files'])}  ·  "
        f"**Rules:** {report['rules_loaded']}  ·  **fail-on:** `{report['fail_on']}`",
        "",
        "| CRITICAL | WARNING | INFO | Needs review | Suppressed |",
        "|---:|---:|---:|---:|---:|",
        f"| {summary[CRITICAL]} | {summary[WARNING]} | {summary[INFO]} | "
        f"{summary['needs_semantic_review']} | {summary.get('suppressed', 0)} |",
        "",
    ]
    if report["findings"]:
        output += [
            "### Findings", "",
            "| Severity | Rule | Location | Confidence | Why |",
            "|---|---|---|---|---|",
        ]
        for finding in report["findings"]:
            why = finding["rationale"].replace("|", "\\|")
            semantic = " ~semantic" if finding["needs_semantic_review"] else ""
            output.append(
                f"| {finding['severity']} | `{finding['rule_id']}`{semantic} | "
                f"`{finding.get('artifact_uri') or finding['file']}:{finding['line']}` | "
                f"{finding.get('confidence', 'high')} | {why} |"
            )
    else:
        output.append("No findings at the selected display threshold.")
    if report.get("scan_diagnostics"):
        output += ["", "### Scan diagnostics", ""]
        output += [f"- `{item['path']}`: {item['message']}"
                   for item in report["scan_diagnostics"]]
    return "\n".join(output) + "\n"


def render_sarif(report: dict, rules: list[dict] | None = None) -> str:
    return json.dumps(build_sarif(report, rules), indent=2, ensure_ascii=False)


def build_sarif(report: dict, rules: list[dict] | None = None) -> dict:
    rules = rules or []
    reports = report.get("reports")
    if isinstance(reports, list):
        runs = [_build_sarif_run(item, rules) for item in reports]
    else:
        runs = [_build_sarif_run(report, rules)]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }


def _build_sarif_run(report: dict, rules: list[dict]) -> dict:
    rule_index = {rule["id"]: index for index, rule in enumerate(rules)}
    driver_rules = [{
        "id": rule["id"],
        "name": _pascal(rule["category"]) + rule["id"].replace("-", ""),
        "shortDescription": {"text": rule.get("rationale") or rule["id"]},
        "defaultConfiguration": {"level": _SARIF_LEVEL.get(rule["severity"], "warning")},
        "properties": {
            "category": rule["category"],
            "layer": rule["layer"],
            "severity": rule["severity"],
        },
    } for rule in rules]
    results = []
    baseline_enabled = bool((report.get("baseline") or {}).get("enabled"))
    for finding in report.get("findings", []):
        if finding.get("semantic_resolved"):
            continue
        if baseline_enabled and not finding.get("new", True):
            continue
        artifact = finding.get("artifact_uri") or finding["file"].split("!", 1)[0]
        result = {
            "ruleId": finding["rule_id"],
            "level": _SARIF_LEVEL.get(finding["severity"], "warning"),
            "message": {"text": finding["rationale"] or finding["rule_id"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": max(1, int(finding["line"])),
                        "snippet": {"text": finding["snippet"]},
                    },
                },
            }],
            "properties": {
                "category": finding["category"],
                "confidence": finding.get("confidence", "high"),
                "needsSemanticReview": finding["needs_semantic_review"],
                "severity": finding["severity"],
                "fingerprint": finding.get("fingerprint"),
                "archiveMember": finding.get("archive_member"),
            },
            "partialFingerprints": {
                "primaryLocationLineHash": finding.get("fingerprint", ""),
            },
        }
        if finding.get("archive_member"):
            result["logicalLocations"] = [{
                "name": finding["archive_member"],
                "kind": "archive-member",
                "fullyQualifiedName": (
                    f"{artifact}!{finding['archive_member']}"
                ),
            }]
        if finding["rule_id"] in rule_index:
            result["ruleIndex"] = rule_index[finding["rule_id"]]
        results.append(result)
    return {
        "tool": {"driver": {
            "name": "skill-auditor",
            "informationUri": "https://github.com/22WELTYANG/skill-auditor",
            "version": report["version"],
            "rules": driver_rules,
        }},
        "automationDetails": {
            "id": report.get("automation_id") or "skill-auditor/default",
        },
        "results": results,
    }


def _pascal(value: str) -> str:
    return "".join(part.capitalize() for part in value.replace("_", "-").split("-"))
