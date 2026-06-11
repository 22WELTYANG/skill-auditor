from __future__ import annotations

from skill_auditor import cli, paths


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

