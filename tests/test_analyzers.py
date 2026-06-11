from __future__ import annotations

import json
import shutil
from pathlib import Path

from skill_auditor import analyzers, cli, formats
from skill_auditor.rules_loader import CRITICAL, INFO, load_rules


FIXTURES = Path(__file__).parent / "fixtures" / "rules"


def test_named_analyzer_corpus():
    manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
    rules = {rule["id"]: rule for rule in load_rules()}
    for item in manifest:
        rule = rules[item["rule_id"]]
        assert rule["severity"] == item["severity"]
        assert item["verdict"] == "DO_NOT_INSTALL"
        assert set(item["formats"]) == {"json", "text", "markdown", "sarif"}
        positive = FIXTURES / item["positive"]
        negative = FIXTURES / item["negative"]
        assert analyzers.run_named_check(
            rule, positive.name, positive.read_text(encoding="utf-8")
        ), item["rule_id"]
        assert not analyzers.run_named_check(
            rule, negative.name, negative.read_text(encoding="utf-8")
        ), item["rule_id"]


def test_named_corpus_produces_all_output_formats(tmp_path):
    manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
    rules = load_rules()
    for item in manifest:
        target = tmp_path / item["rule_id"]
        target.mkdir()
        (target / "SKILL.md").write_text(
            "---\n"
            f"name: fixture-{item['rule_id'].lower()}\n"
            "description: Analyzer output fixture.\n"
            "---\n",
            encoding="utf-8",
        )
        source = FIXTURES / item["positive"]
        shutil.copy2(source, target / source.name)
        report = cli.build_report(
            str(target), target, rules,
            min_severity=INFO, fail_on=CRITICAL,
        )
        assert any(finding["rule_id"] == item["rule_id"] for finding in report["findings"])
        assert report["verdict"] == item["verdict"]
        assert item["rule_id"] in formats.render_json(report)
        assert item["rule_id"] in formats.render_pretty(report, color=False)
        assert item["rule_id"] in formats.render_markdown(report)
        assert item["rule_id"] in formats.render_sarif(report, rules)
