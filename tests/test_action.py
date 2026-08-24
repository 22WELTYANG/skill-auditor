from __future__ import annotations

import io
import re
import tarfile
from pathlib import Path

import pytest
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
        "artifact-name:",
        "sarif-category:",
    ):
        assert name in text
    assert text.index("- name: Scan Skills") < text.index("- name: Upload SARIF")
    assert text.index("- name: Upload SARIF") < text.index("- name: Apply scan gate")
    assert "continue-on-error: true" in text
    assert "*) exit 3 ;;" in text
    assert "outputs['sarif-file'] != ''" in text
    assert "name: ${{ inputs['artifact-name'] }}" in text
    assert "category: ${{ inputs['sarif-category'] }}" in text
    uses = re.findall(r"uses:\s+[^\s@]+@([^\s#]+)", text)
    assert uses and all(re.fullmatch(r"[0-9a-f]{40}", value) for value in uses)


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


def test_action_target_root_link_fails_closed(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    linked = workspace / "linked-skill"
    try:
        linked.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this host")

    with pytest.raises(action_runner.ActionError, match="link or junction"):
        action_runner._workspace_path(workspace, "linked-skill")


def test_action_target_root_junction_check_fails_closed(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "junction-skill"
    target.mkdir()
    monkeypatch.setattr(
        action_runner, "_is_junction", lambda path: path == target
    )

    with pytest.raises(action_runner.ActionError, match="link or junction"):
        action_runner._workspace_path(workspace, "junction-skill")


def test_invalid_action_input_returns_error_contract_without_traceback(
    tmp_path, monkeypatch, capsys
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = tmp_path / "github-output.txt"
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("INPUT_FAIL_ON", "not-a-severity")
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)

    assert action_runner.main() == 0
    values = dict(
        line.split("=", 1)
        for line in output.read_text(encoding="utf-8").splitlines()
    )
    assert values["verdict"] == "ERROR"
    assert values["exit-code"] == "3"
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert "INPUT_FAIL_ON" in captured.err


def test_action_labels_reject_control_characters():
    for value in ("", "../escape", "bad\nname", "bad\u202ename"):
        try:
            action_runner._label("INPUT_ARTIFACT_NAME", value, "fallback")
        except action_runner.ActionError:
            continue
        raise AssertionError(f"unsafe Action label accepted: {value!r}")


def test_action_booleans_use_the_same_lowercase_contract_as_metadata(monkeypatch):
    monkeypatch.setenv("INPUT_UPLOAD_REPORT", "TRUE")
    with pytest.raises(action_runner.ActionError):
        action_runner._boolean("INPUT_UPLOAD_REPORT", True)


@pytest.mark.parametrize(
    "value",
    (
        "../config.yml",
        "dir\\config.yml",
        "C:/config.yml",
        "dir/file:ads",
        "dir/trailing.",
        "NUL.yml",
        "bad\nname.yml",
        "bad\ud800name.yml",
    ),
)
def test_trusted_action_paths_reject_ambiguous_or_nonportable_names(value):
    with pytest.raises(action_runner.ActionError):
        action_runner._trusted_relative_path(value)


def test_trusted_ref_requires_a_full_commit_sha(monkeypatch):
    monkeypatch.setenv("GITHUB_SHA", "HEAD")
    with pytest.raises(action_runner.ActionError, match="full commit SHA"):
        action_runner._trusted_ref({})
    with pytest.raises(action_runner.ActionError, match="full commit SHA"):
        action_runner._trusted_ref(
            {"pull_request": {"base": {"sha": "--upload-pack=evil"}}}
        )
    commit = "A" * 40
    assert action_runner._trusted_ref(
        {"pull_request": {"base": {"sha": commit}}}
    ) == commit.lower()


def test_empty_base_skill_set_gets_a_policy_compatible_baseline(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    monkeypatch.setattr(action_runner, "_event", lambda: {"pull_request": {}})
    monkeypatch.setattr(
        action_runner,
        "_extract_git_archive",
        lambda _workspace, _ref, destination: destination.mkdir(),
    )

    def no_base_skills(*_args, **_kwargs):
        raise action_runner.cli.ScanError("found no valid SKILL.md roots")

    monkeypatch.setattr(action_runner.cli, "build_recursive_report", no_base_skills)
    data = action_runner._action_baseline(
        workspace,
        "a" * 40,
        "auto",
        ".",
        True,
        None,
        temporary,
        "CRITICAL",
        "INFO",
    )
    assert data["tool_version"] == action_runner.cli.VERSION
    assert data["rules_digest"]
    assert data["fingerprints"] == {}


def test_target_new_in_pull_request_gets_an_empty_base_baseline(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    monkeypatch.setattr(action_runner, "_event", lambda: {"pull_request": {}})
    monkeypatch.setattr(
        action_runner,
        "_extract_git_archive",
        lambda _workspace, _ref, destination: destination.mkdir(),
    )
    data = action_runner._action_baseline(
        workspace,
        "a" * 40,
        "auto",
        "new-skill",
        True,
        None,
        temporary,
        "CRITICAL",
        "INFO",
    )
    assert data["tool_version"] == action_runner.cli.VERSION
    assert data["rules_digest"]
    assert data["fingerprints"] == {}


def test_base_scan_filesystem_error_is_not_treated_as_an_empty_baseline(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    monkeypatch.setattr(action_runner, "_event", lambda: {"pull_request": {}})
    monkeypatch.setattr(
        action_runner,
        "_extract_git_archive",
        lambda _workspace, _ref, destination: destination.mkdir(),
    )
    monkeypatch.setattr(
        action_runner.cli,
        "build_recursive_report",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            FileNotFoundError("snapshot file disappeared")
        ),
    )
    with pytest.raises(FileNotFoundError, match="disappeared"):
        action_runner._action_baseline(
            workspace,
            "a" * 40,
            "auto",
            ".",
            True,
            None,
            temporary,
            "CRITICAL",
            "INFO",
        )


def test_incomplete_base_scan_cannot_become_a_baseline(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    monkeypatch.setattr(action_runner, "_event", lambda: {"pull_request": {}})
    monkeypatch.setattr(
        action_runner,
        "_extract_git_archive",
        lambda _workspace, _ref, destination: destination.mkdir(),
    )
    monkeypatch.setattr(
        action_runner.cli,
        "build_recursive_report",
        lambda *_args, **_kwargs: {"scan_status": "INCOMPLETE"},
    )
    with pytest.raises(action_runner.ActionError, match="base scan is incomplete"):
        action_runner._action_baseline(
            workspace,
            "a" * 40,
            "auto",
            ".",
            True,
            None,
            temporary,
            "CRITICAL",
            "INFO",
        )


def test_git_calls_are_noninteractive_bounded_and_do_not_echo_stderr(
    tmp_path, monkeypatch
):
    calls = []

    class Failed:
        returncode = 1
        stdout = b""
        stderr = b"https://user:secret@example.invalid/repo\x1b[31m"

    def fail_git(command, **kwargs):
        calls.append((command, kwargs))
        return Failed()

    monkeypatch.setattr(action_runner.subprocess, "run", fail_git)
    with pytest.raises(action_runner.ActionError) as captured:
        action_runner._git_output(
            tmp_path,
            ["show", f"{'a' * 40}:trusted.yml"],
        )
    assert "secret" not in str(captured.value)
    assert calls
    for command, kwargs in calls:
        assert "credential.helper=" in command
        assert any(value.startswith("core.hooksPath=") for value in command)
        assert kwargs["timeout"] == action_runner.GIT_TIMEOUT_SECONDS
        assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"
        assert kwargs["env"]["GCM_INTERACTIVE"] == "Never"


def _archive_builder(monkeypatch, members):
    def build_archive(_workspace, _ref, destination):
        with tarfile.open(destination, "w") as archive:
            for name, kind in members:
                item = tarfile.TarInfo(name)
                if kind == "directory":
                    item.type = tarfile.DIRTYPE
                    archive.addfile(item)
                elif kind == "symlink":
                    item.type = tarfile.SYMTYPE
                    item.linkname = "../outside"
                    archive.addfile(item)
                else:
                    content = b"payload"
                    item.size = len(content)
                    archive.addfile(item, io.BytesIO(content))

    monkeypatch.setattr(action_runner, "_git_archive", build_archive)


@pytest.mark.parametrize(
    "name",
    ("dir\\escape.txt", "dir/file:ads", "NUL.txt", "dir/trailing."),
)
def test_base_archive_rejects_nonportable_paths(tmp_path, monkeypatch, name):
    _archive_builder(monkeypatch, [(name, "file")])
    with pytest.raises(action_runner.ActionError):
        action_runner._extract_git_archive(
            tmp_path,
            "a" * 40,
            tmp_path / "base",
        )


def test_base_archive_rejects_case_collisions_and_special_entries(
    tmp_path, monkeypatch
):
    _archive_builder(
        monkeypatch,
        [("Folder/", "directory"), ("folder/file.txt", "file")],
    )
    with pytest.raises(action_runner.ActionError, match="colliding paths"):
        action_runner._extract_git_archive(
            tmp_path,
            "a" * 40,
            tmp_path / "case-base",
        )

    _archive_builder(monkeypatch, [("link", "symlink")])
    with pytest.raises(action_runner.ActionError, match="special entry"):
        action_runner._extract_git_archive(
            tmp_path,
            "a" * 40,
            tmp_path / "link-base",
        )


def test_action_output_write_failure_has_no_traceback(monkeypatch, capsys):
    monkeypatch.setattr(
        action_runner,
        "_write_outputs",
        lambda _values: (_ for _ in ()).throw(OSError("cannot open output")),
    )
    assert action_runner.main() == 0
    captured = capsys.readouterr()
    assert "cannot write Action outputs" in captured.err
    assert "Traceback" not in captured.err


def test_unexpected_action_exception_keeps_error_outputs_and_is_sanitized(
    tmp_path, monkeypatch, capsys
):
    output = tmp_path / "github-output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setattr(
        action_runner,
        "_required_env",
        lambda _name: (_ for _ in ()).throw(
            RuntimeError(
                "https://user:secret@example.invalid/repo?token=value\x1b[31m"
            )
        ),
    )
    assert action_runner.main() == 0
    values = dict(
        line.split("=", 1)
        for line in output.read_text(encoding="utf-8").splitlines()
    )
    assert values["verdict"] == "ERROR"
    assert values["exit-code"] == "3"
    captured = capsys.readouterr()
    assert "user:secret" not in captured.err
    assert "token=value" not in captured.err
    assert "\x1b" not in captured.err
    assert "Traceback" not in captured.err


def test_every_external_action_is_pinned_to_a_full_sha_with_version_comment():
    files = [ROOT / "action.yml", *(ROOT / ".github" / "workflows").glob("*.yml")]
    pattern = re.compile(r"^\s*- uses:\s+([^\s@]+)@([^\s#]+)(?:\s+#\s*(v\S+))?", re.MULTILINE)
    found = []
    for path in files:
        for owner, revision, version in pattern.findall(
            path.read_text(encoding="utf-8")
        ):
            found.append((owner, revision, version, path.name))
            assert re.fullmatch(r"[0-9a-f]{40}", revision), (path, owner, revision)
            assert version.startswith("v"), (path, owner, "missing version comment")
    assert found
