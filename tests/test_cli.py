from __future__ import annotations

from pathlib import Path

from skill_auditor import cli
from skill_auditor.rules_loader import CRITICAL, WARNING, load_rules


def test_file_target_returns_controlled_exit_3(tmp_path, capsys):
    target = tmp_path / "file.txt"
    target.write_text("not a skill", encoding="utf-8")
    assert cli.main([str(target), "--format", "json"]) == 3
    captured = capsys.readouterr()
    assert "error:" in captured.err
    assert "Traceback" not in captured.err


def test_min_severity_is_display_only(tmp_path):
    (tmp_path / "SKILL.md").write_text(
        "---\nname: warning-skill\n"
        "description: Warning-only fixture.\n---\n",
        encoding="utf-8",
    )
    (tmp_path / "setup.sh").write_text("chmod 777 deploy.sh\n", encoding="utf-8")
    report = cli.build_report(
        str(tmp_path), tmp_path, load_rules(),
        min_severity=CRITICAL, fail_on=WARNING,
    )
    assert report["summary"][WARNING] >= 1
    assert report["display_summary"][WARNING] == 0
    assert report["findings"] == []
    assert report["verdict"] == "REVIEW_BEFORE_INSTALL"
    assert report["exit_code"] == 1


def test_python_module_and_legacy_parser_accept_bare_path():
    args = cli.build_parser().parse_args(["scan", "example"])
    assert args.command == "scan"
    assert args.target == "example"


def test_unreadable_directory_is_controlled(tmp_path, monkeypatch):
    original = Path.iterdir

    def denied(path):
        if path == tmp_path:
            raise PermissionError("denied")
        return original(path)

    monkeypatch.setattr(Path, "iterdir", denied)
    try:
        cli.validate_skill_directory(tmp_path)
    except cli.ScanError as exc:
        assert "cannot read target directory" in str(exc)
    else:
        raise AssertionError("permission error escaped validation")


def test_invalid_utf8_skill_is_rejected(tmp_path):
    (tmp_path / "SKILL.md").write_bytes(b"\xff\xfe\x00")
    try:
        cli.validate_skill_directory(tmp_path)
    except cli.ScanError as exc:
        assert "UTF-8" in str(exc)
    else:
        raise AssertionError("invalid UTF-8 SKILL.md was accepted")


def test_duplicate_case_insensitive_skill_files_are_rejected(tmp_path):
    first = tmp_path / "SKILL.md"
    second = tmp_path / "skill.md"
    first.write_text("---\nname: a\ndescription: a\n---\n", encoding="utf-8")
    try:
        second.write_text("---\nname: b\ndescription: b\n---\n", encoding="utf-8")
    except OSError:
        return
    if len({item.name for item in tmp_path.iterdir()}) < 2:
        return
    try:
        cli.validate_skill_directory(tmp_path)
    except cli.ScanError as exc:
        assert "exactly one" in str(exc)
    else:
        raise AssertionError("duplicate SKILL.md variants were accepted")
