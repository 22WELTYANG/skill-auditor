#!/usr/bin/env python3
"""
formats.py — render a scan report in one of four shapes.

    pretty    coloured terminal output (the original `text` format; `text` is
              kept as an alias)
    json      machine-readable; the round-1 field set plus `confidence`,
              `suppressed`, and `context`
    sarif     SARIF 2.1.0 (static-analysis interchange; ready for GitHub code
              scanning to render on PRs / the Security tab)
    markdown  a report you can paste straight into an issue or PR

All renderers consume the same `report` dict produced by scan.py. Suppressed
findings live in `report["suppressed"]`; the main `report["findings"]` list and
all counts already exclude them.
"""

from __future__ import annotations

import json
import sys

from rules_loader import CRITICAL, WARNING, INFO

VERDICT_EMOJI = {
    "DO_NOT_INSTALL": "⛔",
    "REVIEW_BEFORE_INSTALL": "⚠️",
    "SAFE_TO_INSTALL": "✅",
}
_SARIF_LEVEL = {CRITICAL: "error", WARNING: "warning", INFO: "note"}


# --------------------------------------------------------------------------- #
# pretty (terminal)
# --------------------------------------------------------------------------- #
def render_pretty(report: dict, *, color: bool | None = None, verbose: bool = False) -> str:
    color = sys.stdout.isatty() if color is None else color

    def c(code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if color else s

    sev_color = {CRITICAL: "1;31", WARNING: "1;33", INFO: "1;36"}
    s = report["summary"]
    out = [
        "=" * 64,
        f" skill-auditor v{report['version']} - scan report",
        f" target : {report['target']}",
        f" files  : {len(report['scanned_files'])} scanned   rules: {report['rules_loaded']}",
        f" totals : {c('1;31', str(s[CRITICAL]) + ' CRITICAL')}  "
        f"{c('1;33', str(s[WARNING]) + ' WARNING')}  "
        f"{c('1;36', str(s[INFO]) + ' INFO')}   "
        f"({s['needs_semantic_review']} need semantic review"
        f"{', ' + str(s['suppressed']) + ' suppressed' if s.get('suppressed') else ''})",
        "=" * 64,
    ]
    if not report["findings"]:
        out += ["", "  No risk patterns matched. (Layer 1 only — still have the",
                "  agent semantically review SKILL.md before trusting it.)", ""]
    for f in report["findings"]:
        out.append(_pretty_finding(f, c, sev_color))

    if verbose and report.get("suppressed"):
        out += ["", "-" * 64, " suppressed (shown by --verbose; excluded from verdict)", "-" * 64]
        for f in report["suppressed"]:
            out.append(_pretty_finding(f, c, sev_color, suppressed=True))

    out += ["", "=" * 64,
            f" VERDICT: {VERDICT_EMOJI.get(report['verdict'], '')} {report['verdict_label']}"
            f"   (fail-on: {report['fail_on']})",
            "=" * 64]
    return "\n".join(out)


def _pretty_finding(f, c, sev_color, *, suppressed: bool = False) -> str:
    tag = c(sev_color.get(f["severity"], "0"), f"[{f['severity']}]")
    mark = "  ~semantic" if f["needs_semantic_review"] else ""
    sup = "  [suppressed]" if suppressed else ""
    conf = f"  conf={f.get('confidence', 'high')}"
    lines = [f"\n{tag} {f['category']}  ({f['rule_id']}){mark}{conf}{sup}",
             f"  {f['file']}:{f['line']}",
             f"    > {f['snippet']}",
             f"    why: {f['rationale']}"]
    if suppressed and f.get("suppressed_reason"):
        lines.append(f"    suppressed: {f['suppressed_reason']}")
    if f["needs_semantic_review"] and f.get("guidance"):
        lines.append(f"    review: {f['guidance']}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# json
# --------------------------------------------------------------------------- #
def render_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False)


# --------------------------------------------------------------------------- #
# markdown
# --------------------------------------------------------------------------- #
def render_markdown(report: dict) -> str:
    s = report["summary"]
    emoji = VERDICT_EMOJI.get(report["verdict"], "")
    out = [
        f"## {emoji} skill-auditor — {report['verdict_label']}",
        "",
        f"**Target:** `{report['target']}`  ",
        f"**Files scanned:** {len(report['scanned_files'])}  ·  "
        f"**Rules:** {report['rules_loaded']}  ·  **fail-on:** `{report['fail_on']}`",
        "",
        f"| CRITICAL | WARNING | INFO | Needs review | Suppressed |",
        f"|---:|---:|---:|---:|---:|",
        f"| {s[CRITICAL]} | {s[WARNING]} | {s[INFO]} | "
        f"{s['needs_semantic_review']} | {s.get('suppressed', 0)} |",
        "",
    ]
    if report["findings"]:
        out += ["### Findings", "",
                "| Severity | Rule | Location | Confidence | Why |",
                "|---|---|---|---|---|"]
        for f in report["findings"]:
            why = f["rationale"].replace("|", "\\|")
            loc = f"`{f['file']}:{f['line']}`"
            sem = " ~semantic" if f["needs_semantic_review"] else ""
            out.append(f"| {f['severity']} | `{f['rule_id']}`{sem} | {loc} "
                       f"| {f.get('confidence', 'high')} | {why} |")
        out.append("")
    else:
        out += ["No deterministic risk patterns matched.", ""]

    if report.get("suppressed"):
        out += [f"<details><summary>{len(report['suppressed'])} suppressed</summary>",
                "", "| Severity | Rule | Location | Reason |", "|---|---|---|---|"]
        for f in report["suppressed"]:
            reason = (f.get("suppressed_reason") or "").replace("|", "\\|")
            out.append(f"| {f['severity']} | `{f['rule_id']}` | "
                       f"`{f['file']}:{f['line']}` | {reason} |")
        out += ["", "</details>", ""]
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# sarif 2.1.0
# --------------------------------------------------------------------------- #
def render_sarif(report: dict, rules: list[dict] | None = None) -> str:
    return json.dumps(build_sarif(report, rules), indent=2, ensure_ascii=False)


def build_sarif(report: dict, rules: list[dict] | None = None) -> dict:
    rules = rules or []
    driver_rules = []
    rule_index: dict[str, int] = {}
    for i, r in enumerate(rules):
        rule_index[r["id"]] = i
        driver_rules.append({
            "id": r["id"],
            "name": _pascal(r["category"]) + r["id"].replace("-", ""),
            "shortDescription": {"text": r.get("rationale") or r["id"]},
            "defaultConfiguration": {"level": _SARIF_LEVEL.get(r["severity"], "warning")},
            "properties": {
                "category": r["category"],
                "layer": r["layer"],
                "severity": r["severity"],
            },
        })

    results = []
    for f in report["findings"]:
        res = {
            "ruleId": f["rule_id"],
            "level": _SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": f["rationale"] or f["rule_id"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": max(1, int(f["line"])),
                               "snippet": {"text": f["snippet"]}},
                },
            }],
            "partialFingerprints": {
                "skillAuditorRuleLine": f"{f['rule_id']}:{f['file']}:{f['line']}",
            },
            "properties": {
                "category": f["category"],
                "confidence": f.get("confidence", "high"),
                "needsSemanticReview": f["needs_semantic_review"],
            },
        }
        if f["rule_id"] in rule_index:
            res["ruleIndex"] = rule_index[f["rule_id"]]
        results.append(res)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "skill-auditor",
                    "informationUri": "https://github.com/22WELTYANG/skill-auditor",
                    "version": report["version"],
                    "rules": driver_rules,
                },
            },
            "results": results,
        }],
    }


def _pascal(s: str) -> str:
    return "".join(part.capitalize() for part in s.replace("_", "-").split("-"))
