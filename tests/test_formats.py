from __future__ import annotations

import json
from pathlib import Path

from skill_auditor import cli, formats
from skill_auditor.rules_loader import CRITICAL, INFO, load_rules


def _clean_report():
    root = Path(__file__).resolve().parents[1] / "examples" / "clean-skill"
    rules = load_rules()
    return rules, cli.build_report(
        str(root), root, rules, min_severity=INFO, fail_on=CRITICAL
    )


def test_json_text_markdown_and_sarif_are_well_formed():
    rules, report = _clean_report()
    assert json.loads(formats.render_json(report))["verdict"] == "SAFE_TO_INSTALL"
    assert "SAFE TO INSTALL" in formats.render_pretty(report, color=False)
    assert "skill-auditor" in formats.render_markdown(report)
    sarif = json.loads(formats.render_sarif(report, rules))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1

