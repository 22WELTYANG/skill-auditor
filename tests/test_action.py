from __future__ import annotations

from pathlib import Path

import yaml

from skill_auditor import action_runner


ROOT = Path(__file__).resolve().parents[1]


def test_action_metadata_has_required_inputs_and_upload_order():
    text = (ROOT / "action.yml").read_text(encoding="utf-8")
    action = yaml.safe_load(text)
    hooks = yaml.safe_load(
        (ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
    )
    assert action["runs"]["using"] == "composite"
    assert hooks[0]["pass_filenames"] is False
    assert hooks[0]["always_run"] is True
    for name in (
        "path:",
        "recursive:",
        "fail-on:",
        "min-severity:",
        "config:",
        "baseline:",
        "upload-sarif:",
        "upload-report:",
    ):
        assert name in text
    assert text.index("- name: Scan Skills") < text.index("- name: Upload SARIF")
    assert text.index("- name: Upload SARIF") < text.index("- name: Apply scan gate")
    assert "continue-on-error: true" in text


def test_action_path_must_stay_inside_workspace(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    inside = workspace / "skill"
    inside.mkdir()
    assert action_runner._workspace_path(workspace, "skill") == inside
    try:
        action_runner._workspace_path(workspace, "../outside")
    except (action_runner.ActionError, FileNotFoundError):
        pass
    else:
        raise AssertionError("action accepted a path outside GITHUB_WORKSPACE")
