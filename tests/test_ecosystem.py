from __future__ import annotations

from pathlib import Path

from skill_auditor import baseline, cache, cli, formats, integrity
from skill_auditor.rules_loader import CRITICAL, INFO, WARNING, load_rules


def _skill(root: Path, name: str, script: str = "") -> None:
    root.mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\n"
        f"name: {name}\n"
        "description: Ecosystem regression fixture.\n"
        "---\n",
        encoding="utf-8",
    )
    if script:
        (root / "setup.sh").write_text(script, encoding="utf-8")


def test_sarif_uses_repository_paths_fingerprints_and_automation(tmp_path):
    repo = tmp_path / "repo"
    skill = repo / "skills" / "demo"
    _skill(skill, "demo", "chmod 777 deploy.sh\n")
    rules = load_rules()
    report = cli.build_report(
        str(skill),
        skill,
        rules,
        min_severity=INFO,
        fail_on=CRITICAL,
        source_root=repo,
    )
    finding = next(item for item in report["findings"] if item["rule_id"] == "SHELL-007")
    assert finding["file"] == "setup.sh"
    assert finding["artifact_uri"] == "skills/demo/setup.sh"
    assert len(finding["fingerprint"]) == 64
    sarif = formats.build_sarif(report, rules)
    run = sarif["runs"][0]
    result = next(item for item in run["results"] if item["ruleId"] == "SHELL-007")
    assert run["automationDetails"]["id"] == "skill-auditor/skills/demo"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"] == {
        "uri": "skills/demo/setup.sh",
        "uriBaseId": "%SRCROOT%",
    }
    assert result["partialFingerprints"]["primaryLocationLineHash"] == finding["fingerprint"]


def test_recursive_scan_creates_one_sarif_run_per_skill(tmp_path):
    repo = tmp_path / "repo"
    _skill(repo / "skills" / "one", "one")
    _skill(repo / "skills" / "two", "two", "chmod 777 deploy.sh\n")
    rules = load_rules()
    report = cli.build_recursive_report(
        str(repo),
        repo,
        rules,
        min_severity=INFO,
        fail_on=CRITICAL,
        source_root=repo,
        use_cache=False,
    )
    assert len(report["reports"]) == 2
    runs = formats.build_sarif(report, rules)["runs"]
    assert {run["automationDetails"]["id"] for run in runs} == {
        "skill-auditor/skills/one",
        "skill-auditor/skills/two",
    }


def test_recursive_display_threshold_does_not_change_gate(tmp_path):
    repo = tmp_path / "repo"
    _skill(repo / "skill", "threshold-demo", "chmod 777 deploy.sh\n")
    report = cli.build_recursive_report(
        str(repo),
        repo,
        load_rules(),
        min_severity=CRITICAL,
        fail_on=WARNING,
        source_root=repo,
        use_cache=False,
    )
    assert report["summary"][WARNING] == 1
    assert report["display_summary"][WARNING] == 0
    assert report["findings"] == []
    assert report["verdict"] == "REVIEW_BEFORE_INSTALL"
    assert report["exit_code"] == 1


def test_recursive_lock_create_and_verify_contract(tmp_path):
    repo = tmp_path / "repo"
    first = repo / "skills" / "one"
    second = repo / "skills" / "two"
    _skill(first, "one")
    _skill(second, "two")
    lock_path = tmp_path / "recursive.lock"

    common = [str(repo), "--recursive", "--no-cache"]
    assert cli.main(
        ["lock", "create", *common, "--output", str(lock_path)]
    ) == 0
    assert cli.main(
        ["lock", "verify", *common, "--lock", str(lock_path)]
    ) == 0

    (second / "notes.md").write_text("changed\n", encoding="utf-8")
    assert cli.main(
        ["lock", "verify", *common, "--lock", str(lock_path)]
    ) == 1


def test_baseline_keeps_full_report_but_only_gates_new_findings(tmp_path):
    skill = tmp_path / "skill"
    _skill(skill, "baseline-demo", "chmod 777 first.sh\n")
    rules = load_rules()
    original = cli.build_report(
        str(skill), skill, rules, min_severity=INFO, fail_on=WARNING
    )
    trusted = baseline.build(original)
    unchanged = cli.build_report(
        str(skill),
        skill,
        rules,
        min_severity=INFO,
        fail_on=WARNING,
        baseline_data=trusted,
    )
    assert unchanged["summary"][WARNING] >= 1
    assert unchanged["gate_summary"]["total"] == 0
    assert unchanged["full_verdict"] == "REVIEW_BEFORE_INSTALL"
    assert unchanged["verdict"] == "SAFE_TO_INSTALL"
    assert unchanged["exit_code"] == 0
    assert all(not item["new"] for item in unchanged["findings"])

    (skill / "setup.sh").write_text(
        "chmod 777 first.sh\nchmod 777 second.sh\n",
        encoding="utf-8",
    )
    changed = cli.build_report(
        str(skill),
        skill,
        rules,
        min_severity=INFO,
        fail_on=WARNING,
        baseline_data=trusted,
    )
    assert changed["gate_summary"][WARNING] == 1
    assert changed["exit_code"] == 1


def test_cache_and_lock_are_invalidated_by_content_changes(tmp_path):
    skill = tmp_path / "skill"
    cache_dir = tmp_path / "cache"
    _skill(skill, "cache-demo")
    rules = load_rules()
    first = cli.build_report_cached(
        str(skill),
        skill,
        rules,
        min_severity=INFO,
        fail_on=CRITICAL,
        cache_directory=cache_dir,
    )
    second = cli.build_report_cached(
        str(skill),
        skill,
        rules,
        min_severity=INFO,
        fail_on=CRITICAL,
        cache_directory=cache_dir,
    )
    assert first["cache"]["hit"] is False
    assert second["cache"]["hit"] is True
    lock = integrity.build(second)

    (skill / "notes.md").write_text("changed\n", encoding="utf-8")
    third = cli.build_report_cached(
        str(skill),
        skill,
        rules,
        min_severity=INFO,
        fail_on=CRITICAL,
        cache_directory=cache_dir,
    )
    assert third["cache"]["hit"] is False
    assert "content_hash" in integrity.differences(third, lock)


def test_cache_directory_inside_target_is_rejected(tmp_path):
    skill = tmp_path / "skill"
    _skill(skill, "cache-boundary")
    try:
        cache.validate_directory(skill / ".cache", skill)
    except cache.CacheError:
        pass
    else:
        raise AssertionError("target-owned cache directory was accepted")


def test_recursive_scan_rejects_repository_owned_config_and_cache(tmp_path):
    repo = tmp_path / "repo"
    _skill(repo / "skill", "recursive-boundary")
    config = repo / ".skill-auditor.yml"
    config.write_text("ignore_paths: []\n", encoding="utf-8")
    rules = load_rules()
    for kwargs in (
        {"config_path": config, "use_cache": False},
        {"cache_directory": repo / ".cache", "use_cache": True},
    ):
        try:
            cli.build_recursive_report(
                str(repo),
                repo,
                rules,
                min_severity=INFO,
                fail_on=CRITICAL,
                source_root=repo,
                **kwargs,
            )
        except (cli.ScanError, cache.CacheError):
            continue
        raise AssertionError("recursive scan accepted target-owned trust state")
