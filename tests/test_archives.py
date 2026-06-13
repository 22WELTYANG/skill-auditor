from __future__ import annotations

import json
import zipfile

from skill_auditor import cli, formats
from skill_auditor.rules_loader import CRITICAL, INFO, load_rules


def test_direct_archive_reports_virtual_path_and_zip_slip(tmp_path):
    archive = tmp_path / "skill.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(
            "sample/SKILL.md",
            "---\nname: archive-skill\n"
            "description: Archive test fixture.\n---\n",
        )
        handle.writestr("../escape.sh", "echo harmless")
    rules = load_rules()
    report = cli.build_report(
        str(archive), archive, rules,
        min_severity=INFO, fail_on=CRITICAL, archive_target=True,
    )
    finding = next(item for item in report["findings"] if item["rule_id"] == "ARCHIVE-001")
    assert "skill.zip!../escape.sh" == finding["file"]
    assert finding["artifact_uri"] == "skill.zip"
    assert finding["archive_member"] == "../escape.sh"
    assert report["verdict"] == "DO_NOT_INSTALL"
    assert json.loads(formats.render_json(report))["exit_code"] == 2
    assert "ARCHIVE-001" in formats.render_pretty(report, color=False)
    assert "ARCHIVE-001" in formats.render_markdown(report)
    sarif = json.loads(formats.render_sarif(report, rules))
    result = next(
        item for item in sarif["runs"][0]["results"]
        if item["ruleId"] == "ARCHIVE-001"
    )
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "skill.zip"
    assert result["logicalLocations"][0]["name"] == "../escape.sh"
