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
    pretty = formats.render_pretty(report, color=False)
    assert "SAFE TO INSTALL" in pretty
    assert "status : COMPLETE" in pretty
    assert "deprecated finding aliases:" in pretty
    markdown = formats.render_markdown(report)
    assert "skill-auditor" in markdown
    assert "**Scan status:** `COMPLETE`" in markdown
    assert "**Deprecated finding aliases:**" in markdown
    sarif = json.loads(formats.render_sarif(report, rules))
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["properties"]["reportSchema"] == "skill-auditor-report/v1"
    assert run["properties"]["scanStatus"] == "COMPLETE"
    assert run["properties"]["source"] == report["source"]
    assert run["properties"]["coverage"] == report["coverage"]
    assert run["properties"]["deprecations"] == report["deprecations"]
    assert run["invocations"][0]["executionSuccessful"] is True


def test_incomplete_report_is_visible_in_sarif_invocation(tmp_path):
    (tmp_path / "SKILL.md").write_text(
        "---\nname: incomplete\ndescription: Incomplete fixture.\n---\n",
        encoding="utf-8",
    )
    (tmp_path / "payload.bin").write_bytes(b"\x00uninspectable")
    rules = load_rules()
    report = cli.build_report(
        str(tmp_path), tmp_path, rules, min_severity=INFO, fail_on=CRITICAL
    )
    run = json.loads(formats.render_sarif(report, rules))["runs"][0]
    assert run["properties"]["scanStatus"] == "INCOMPLETE"
    assert run["invocations"][0]["executionSuccessful"] is False
    assert run["invocations"][0]["exitCode"] == 3
    assert run["invocations"][0]["toolExecutionNotifications"]
