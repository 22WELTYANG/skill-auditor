from __future__ import annotations

import os

import pytest

from skill_auditor import cli
from skill_auditor.rules_loader import CRITICAL, INFO, load_rules


def test_external_symlink_is_reported_and_not_followed(tmp_path):
    target = tmp_path / "skill"
    target.mkdir()
    (target / "SKILL.md").write_text(
        "---\nname: linked-skill\n"
        "description: Link fixture.\n---\n",
        encoding="utf-8",
    )
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = target / "outside-link"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")
    report = cli.build_report(
        str(target), target, load_rules(),
        min_severity=INFO, fail_on=CRITICAL,
    )
    assert any(item["rule_id"] == "BOUNDARY-001" for item in report["findings"])
    assert "outside-link" not in report["scanned_files"]

