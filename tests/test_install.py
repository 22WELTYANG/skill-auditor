from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from skill_auditor import cli, installer, paths


ROOT = Path(__file__).resolve().parents[1]


def test_install_uses_validated_child_destination(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text(
        "---\nname: installed-skill\n"
        "description: Install fixture.\n---\n",
        encoding="utf-8",
    )
    destination_root = tmp_path / "skills"
    monkeypatch.setenv("SKILLS_DIR", str(destination_root))
    installed = cli._do_install(source, "installed-skill")
    assert installed == [destination_root / "installed-skill"]
    assert (installed[0] / "SKILL.md").is_file()


def test_invalid_install_names_are_rejected():
    for value in ("", ".", "..", "../escape", "C:\\escape", "CON", "bad name"):
        try:
            paths.validate_skill_name(value)
        except paths.PathSafetyError:
            continue
        raise AssertionError(f"unsafe name accepted: {value!r}")


def test_codex_home_is_preferred_and_legacy_duplicate_is_removed(
    tmp_path, monkeypatch
):
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    monkeypatch.delenv("SKILLS_DIR", raising=False)
    monkeypatch.setenv("CODEX_HOME", str(home / ".codex"))
    monkeypatch.setattr(
        paths,
        "_expand",
        lambda value: Path(str(value).replace("~", str(home), 1)),
    )

    assert paths.install_targets() == [
        home / ".codex" / "skills",
        home / ".claude" / "skills",
        home / ".agents" / "skills",
        home / ".cursor" / "skills",
    ]


def _entry(root, relative):
    content = (root / relative).read_bytes()
    return installer.PayloadEntry(
        path=relative,
        size=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        mode=0o644,
        content=content,
    )


def test_manifest_install_copies_only_explicit_entries_to_every_target(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("skill\n", encoding="utf-8")
    (source / "src").mkdir()
    (source / "src" / "tool.py").write_text("print('ok')\n", encoding="utf-8")
    (source / "untracked-build.bin").write_bytes(b"do not install")
    targets = [tmp_path / "one root", tmp_path / "two root"]
    for target in targets:
        previous = target / "demo"
        previous.mkdir(parents=True)
        (previous / "obsolete.txt").write_text("old\n", encoding="utf-8")

    installed = installer.install_snapshot(
        [_entry(source, "SKILL.md"), _entry(source, "src/tool.py")],
        "demo",
        targets=targets,
    )

    assert installed == [target / "demo" for target in targets]
    for destination in installed:
        assert (destination / "SKILL.md").read_text(encoding="utf-8") == "skill\n"
        assert (destination / "src" / "tool.py").is_file()
        assert not (destination / "untracked-build.bin").exists()
        assert not (destination / "obsolete.txt").exists()


def test_manifest_install_rejects_link_or_junction_destination(
    tmp_path, monkeypatch
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("skill\n", encoding="utf-8")
    target = tmp_path / "skills"
    destination = target / "demo"
    destination.mkdir(parents=True)
    real_is_link = installer._is_link
    monkeypatch.setattr(
        installer,
        "_is_link",
        lambda path: path == destination or real_is_link(path),
    )

    with pytest.raises(installer.InstallError, match="unsafe destination"):
        installer.install_snapshot(
            [_entry(source, "SKILL.md")], "demo", targets=[target]
        )


def test_manifest_install_rolls_back_every_target_on_commit_failure(
    tmp_path, monkeypatch
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("new\n", encoding="utf-8")
    targets = [tmp_path / "one", tmp_path / "two"]
    for target in targets:
        destination = target / "demo"
        destination.mkdir(parents=True)
        (destination / "SKILL.md").write_text("old\n", encoding="utf-8")

    real_replace = installer._replace
    staging_commits = 0

    def fail_second_staging_commit(source_path, destination_path):
        nonlocal staging_commits
        if ".staging-" in source_path.name and destination_path.name == "demo":
            staging_commits += 1
            if staging_commits == 2:
                raise OSError("simulated commit failure")
        return real_replace(source_path, destination_path)

    monkeypatch.setattr(installer, "_replace", fail_second_staging_commit)
    with pytest.raises(installer.InstallError, match="simulated commit failure"):
        installer.install_snapshot(
            [_entry(source, "SKILL.md")],
            "demo",
            targets=targets,
        )

    for target in targets:
        destination = target / "demo"
        assert (destination / "SKILL.md").read_text(encoding="utf-8") == "old\n"
        assert not list(target.glob(".demo.staging-*"))
        assert not list(target.glob(".demo.backup-*"))


def test_manifest_install_uses_captured_bytes_when_source_changes(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("original\n", encoding="utf-8")
    entry = _entry(source, "SKILL.md")
    (source / "SKILL.md").write_text("mutated\n", encoding="utf-8")

    installed = installer.install_snapshot(
        [entry],
        "demo",
        targets=[tmp_path / "skills"],
    )
    assert (installed[0] / "SKILL.md").read_text(encoding="utf-8") == "original\n"


def test_manifest_install_verifies_every_staging_tree_before_commit(
    tmp_path, monkeypatch
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("approved\n", encoding="utf-8")
    target = tmp_path / "skills"
    previous = target / "demo"
    previous.mkdir(parents=True)
    (previous / "SKILL.md").write_text("previous\n", encoding="utf-8")
    real_stage = installer._stage_payload

    def corrupt_staging(staging, payload):
        real_stage(staging, payload)
        (staging / "SKILL.md").write_text("tampered\n", encoding="utf-8")

    monkeypatch.setattr(installer, "_stage_payload", corrupt_staging)
    with pytest.raises(installer.InstallError, match="staged payload bytes"):
        installer.install_snapshot(
            [_entry(source, "SKILL.md")], "demo", targets=[target]
        )
    assert (previous / "SKILL.md").read_text(encoding="utf-8") == "previous\n"


def test_manifest_install_cleans_all_staging_when_a_write_fails(
    tmp_path, monkeypatch
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("approved\n", encoding="utf-8")
    targets = [tmp_path / "one", tmp_path / "two"]
    real_stage = installer._stage_payload
    calls = 0

    def fail_second_write(staging, payload):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated write failure")
        real_stage(staging, payload)

    monkeypatch.setattr(installer, "_stage_payload", fail_second_write)
    with pytest.raises(installer.InstallError, match="simulated write failure"):
        installer.install_snapshot(
            [_entry(source, "SKILL.md")], "demo", targets=targets
        )
    for target in targets:
        assert not (target / "demo").exists()
        assert not list(target.glob(".demo.staging-*"))


def test_self_payload_uses_only_git_tracked_allowlisted_files(tmp_path):
    source = tmp_path / "source"
    (source / "scripts").mkdir(parents=True)
    (source / "SKILL.md").write_text("skill\n", encoding="utf-8")
    (source / "LICENSE").write_text("license\n", encoding="utf-8")
    (source / "scripts" / "scan.py").write_text("pass\n", encoding="utf-8")
    (source / "scripts" / "run_tests.py").write_text("broken\n", encoding="utf-8")
    (source / "scripts" / "build.pyc").write_bytes(b"cache")
    (source / "tests").mkdir()
    (source / "tests" / "tracked.py").write_text("pass\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    subprocess.run(
        ["git", "config", "core.autocrlf", "false"], cwd=source, check=True
    )
    subprocess.run(
        [
            "git",
            "add",
            "SKILL.md",
            "LICENSE",
            "scripts/scan.py",
            "scripts/run_tests.py",
            "tests/tracked.py",
        ],
        cwd=source,
        check=True,
    )
    installer.write_payload_manifest(source)
    subprocess.run(["git", "add", installer.PAYLOAD_MANIFEST], cwd=source, check=True)
    _commit_fixture(source)

    entries = installer.self_payload(source)
    assert [entry.path for entry in entries] == [
        "LICENSE",
        "SKILL.md",
        "scripts/scan.py",
    ]
    assert installer.PAYLOAD_MANIFEST not in [entry.path for entry in entries]

    (source / "scripts" / "scan.py").write_text("changed\n", encoding="utf-8")
    with pytest.raises(installer.InstallError, match="differs from the reviewed"):
        installer.self_payload(source)


@pytest.mark.parametrize("staged", [False, True])
def test_self_payload_rejects_matching_payload_and_manifest_drift(tmp_path, staged):
    source = tmp_path / "source"
    source.mkdir()
    (source / "SKILL.md").write_text("safe\n", encoding="utf-8")
    (source / "LICENSE").write_text("license\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    subprocess.run(
        ["git", "config", "core.autocrlf", "false"], cwd=source, check=True
    )
    subprocess.run(["git", "add", "SKILL.md", "LICENSE"], cwd=source, check=True)
    installer.write_payload_manifest(source)
    subprocess.run(["git", "add", installer.PAYLOAD_MANIFEST], cwd=source, check=True)
    _commit_fixture(source)

    (source / "SKILL.md").write_text("malicious but checksummed\n", encoding="utf-8")
    installer.write_payload_manifest(source)
    if staged:
        subprocess.run(
            ["git", "add", "SKILL.md", installer.PAYLOAD_MANIFEST],
            cwd=source,
            check=True,
        )
    with pytest.raises(installer.InstallError, match="differs from the reviewed"):
        installer.self_payload(source)


def _commit_fixture(source):
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgSign=false",
            "-c",
            f"core.hooksPath={os.devnull}",
            "commit",
            "-qm",
            "fixture",
        ],
        cwd=source,
        check=True,
    )


def test_shipped_payload_manifest_is_complete_and_not_self_referential():
    recorded = json.loads(
        (ROOT / installer.PAYLOAD_MANIFEST).read_text(encoding="utf-8")
    )
    installed_paths = {item["path"] for item in recorded["files"]}
    assert "LICENSE" in installed_paths
    assert "agents/openai.yaml" in installed_paths
    assert "schemas/skill-auditor-report-v1.schema.json" in installed_paths
    assert "src/skill_auditor/schemas/skill-auditor-report-v1.schema.json" in installed_paths
    assert installer.PAYLOAD_MANIFEST not in installed_paths
    assert "scripts/run_tests.py" not in installed_paths
    assert "scripts/research_corpus.py" not in installed_paths
    assert not any(path.startswith(("build/", "dist/", "tests/")) for path in installed_paths)
    for item in recorded["files"]:
        content = (ROOT / item["path"]).read_bytes()
        assert len(content) == item["size"]
        assert hashlib.sha256(content).hexdigest() == item["sha256"]


def test_repository_payload_checksum_manifest_is_current():
    if not (ROOT / ".git").exists():
        pytest.skip("manifest generation requires a Git checkout")
    recorded = json.loads(
        (ROOT / installer.PAYLOAD_MANIFEST).read_text(encoding="utf-8")
    )
    expected = installer.build_payload_manifest(ROOT, include_untracked=True)
    assert recorded == expected


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "dir/file:ads",
        "dir/trailing.",
        "dir/trailing ",
        "CON",
        "NUL.txt",
        "x/COM1.py",
        "bad\ud800name",
    ],
)
def test_payload_rejects_windows_alias_and_ads_paths(unsafe_path):
    with pytest.raises(installer.InstallError, match="payload path"):
        installer.PayloadEntry(
            unsafe_path,
            0,
            hashlib.sha256(b"").hexdigest(),
            0o644,
            b"",
        )


def test_payload_rejects_case_insensitive_collisions(tmp_path):
    content = b"skill\n"
    digest = hashlib.sha256(content).hexdigest()
    entries = [
        installer.PayloadEntry("SKILL.md", len(content), digest, 0o644, content),
        installer.PayloadEntry("skill.MD", len(content), digest, 0o644, content),
    ]
    with pytest.raises(installer.InstallError, match="duplicate payload path"):
        installer.install_snapshot(entries, "demo", targets=[tmp_path / "skills"])


def test_payload_rejects_unicode_normalization_collisions(tmp_path):
    content = b"same\n"
    digest = hashlib.sha256(content).hexdigest()
    entries = [
        installer.PayloadEntry("caf\u00e9.txt", len(content), digest, 0o644, content),
        installer.PayloadEntry("cafe\u0301.txt", len(content), digest, 0o644, content),
    ]
    with pytest.raises(installer.InstallError, match="duplicate payload path"):
        installer.install_snapshot(entries, "demo", targets=[tmp_path / "skills"])


def test_installer_argument_errors_return_three_without_traceback(capsys):
    assert installer.main([]) == 3
    captured = capsys.readouterr()
    assert "invalid installer arguments" in captured.err
    assert "Traceback" not in captured.err


def test_installer_errors_redact_credentials_and_terminal_controls(
    monkeypatch, capsys
):
    monkeypatch.setattr(
        installer,
        "self_payload",
        lambda _source: (_ for _ in ()).throw(
            installer.InstallError(
                "https://user:secret@example.invalid/repo?token=value\x1b[31m"
            )
        ),
    )
    assert installer.main(["--source", "."]) == 3
    captured = capsys.readouterr()
    assert "user:secret" not in captured.err
    assert "token=value" not in captured.err
    assert "\x1b" not in captured.err


def test_shell_wrapper_normalizes_child_failure_to_three(tmp_path):
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is not available")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_python = fake_bin / "python3"
    with fake_python.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("#!/bin/sh\nexit 42\n")
    fake_python.chmod(0o755)
    environment = os.environ.copy()
    environment["PATH"] = str(fake_bin) + os.pathsep + environment.get("PATH", "")
    result = subprocess.run(
        [bash, str(ROOT / "install.sh")],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 3


def test_install_wrappers_only_accept_a_reviewed_local_checkout():
    shell = (ROOT / "install.sh").read_text(encoding="utf-8")
    powershell = (ROOT / "install.ps1").read_text(encoding="utf-8")
    assert "git clone" not in shell
    assert "git clone" not in powershell
    assert "exit 3" in shell
    assert "exit 3" in powershell
