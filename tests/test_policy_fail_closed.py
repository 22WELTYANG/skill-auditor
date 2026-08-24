from __future__ import annotations

import json
import stat
import zipfile

import pytest

from skill_auditor import baseline, cli, config, integrity, scanner, semantic
from skill_auditor.rules_loader import RuleError, load_rules


def test_baseline_rejects_tool_or_rule_policy_drift():
    trusted = {
        "tool_version": "0.8.0",
        "rules_digest": "a" * 64,
        "fingerprints": {},
    }
    with pytest.raises(baseline.BaselineError, match="tool version"):
        baseline.validate_compatibility(
            trusted, tool_version="0.9.0", rules_digest="a" * 64
        )
    with pytest.raises(baseline.BaselineError, match="rules digest"):
        baseline.validate_compatibility(
            trusted, tool_version="0.8.0", rules_digest="b" * 64
        )


def test_empty_unknown_and_unsupported_rules_fail_closed(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(RuleError, match="no usable rules"):
        load_rules(empty)

    unknown = tmp_path / "unknown"
    unknown.mkdir()
    (unknown / "rules.yaml").write_text(
        "rules:\n"
        "  - id: TEST-001\n"
        "    category: custom\n"
        "    severity: WARNING\n"
        "    layer: deterministic\n"
        "    check: made-up-check\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleError, match="unknown check"):
        load_rules(unknown)

    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "rules.yaml").write_text(
        "rules:\n  - id: TEST-001\n    nested:\n      value: nope\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleError, match="unsupported YAML structure"):
        load_rules(nested)


def test_custom_rules_cannot_replace_reserved_engine_integrity_rules(
    tmp_path, capsys, monkeypatch
):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "rules.yaml").write_text(
        "rules:\n"
        "  - id: ARCHIVE-002\n"
        "    category: custom\n"
        "    severity: INFO\n"
        "    layer: deterministic\n"
        "    check: archive-link\n",
        encoding="utf-8",
    )

    with pytest.raises(RuleError, match="reserved by the scan engine"):
        load_rules(rules_dir)

    target = tmp_path / "target"
    target.mkdir()
    (target / "SKILL.md").write_text(
        "---\nname: archive-override\ndescription: Regression fixture.\n---\n",
        encoding="utf-8",
    )
    archive = target / "payload.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        member = zipfile.ZipInfo("linked-payload")
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        handle.writestr(member, "outside")

    assert cli.main(
        [str(target), "--rules-dir", str(rules_dir), "--format", "json"]
    ) == 3
    scan_output = capsys.readouterr()
    assert scan_output.out == ""
    assert "reserved by the scan engine" in scan_output.err
    assert "SAFE_TO_INSTALL" not in scan_output.err
    assert "Traceback" not in scan_output.err

    install_root = tmp_path / "installed"
    monkeypatch.setenv("SKILLS_DIR", str(install_root))
    assert cli.main(
        [
            "install",
            str(target),
            "--rules-dir",
            str(rules_dir),
        ]
    ) == 3
    install_output = capsys.readouterr()
    assert not install_root.exists()
    assert "reserved by the scan engine" in install_output.err
    assert "Traceback" not in install_output.err

    override = {
        "id": "ARCHIVE-002",
        "category": "custom",
        "severity": "INFO",
        "layer": "deterministic",
    }
    protected = scanner._engine_rule({"ARCHIVE-002": override}, "ARCHIVE-002")
    assert protected["severity"] == "CRITICAL"
    assert protected["category"] == "archive-risk"


@pytest.mark.parametrize(
    "unsupported",
    [
        "!!str rm\\s+-rf",
        "&pattern rm\\s+-rf",
        "*pattern",
        "|",
        ">-",
        "[rm\\s+-rf]",
        "{pattern: rm\\s+-rf}",
        "rm\\s+-rf # destructive delete",
        "rm\\s+-rf: nested mapping",
        '"rm\\\\s+-rf"',
    ],
)
def test_rule_yaml_tags_anchors_blocks_and_flow_values_are_rejected(
    tmp_path, unsupported
):
    rules_dir = tmp_path / "tagged-rules"
    rules_dir.mkdir()
    (rules_dir / "rules.yaml").write_text(
        "rules:\n"
        "  - id: TEST-001\n"
        "    category: dangerous-shell\n"
        "    severity: CRITICAL\n"
        "    layer: deterministic\n"
        f"    pattern: {unsupported}\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleError, match="not supported"):
        load_rules(rules_dir)


@pytest.mark.parametrize(
    "pattern",
    [
        "!!str rm\\s+-rf",
        "rm\\s+-rf # destructive delete",
        '"rm\\\\s+-rf"',
    ],
)
def test_unsupported_rule_yaml_cannot_turn_malicious_target_safe(
    tmp_path, capsys, pattern
):
    rules_dir = tmp_path / "tagged-rules"
    rules_dir.mkdir()
    (rules_dir / "rules.yaml").write_text(
        "rules:\n"
        "  - id: TEST-001\n"
        "    category: dangerous-shell\n"
        "    severity: CRITICAL\n"
        "    layer: deterministic\n"
        f"    pattern: {pattern}\n",
        encoding="utf-8",
    )
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: tagged-rule-target\ndescription: Regression fixture.\n---\n",
        encoding="utf-8",
    )
    (skill / "run.sh").write_text("rm -rf /\n", encoding="utf-8")

    assert cli.main([str(skill), "--rules-dir", str(rules_dir), "--format", "json"]) == 3
    captured = capsys.readouterr()
    assert "not supported" in captured.err
    assert "SAFE_TO_INSTALL" not in captured.out
    assert "Traceback" not in captured.err


def test_trusted_assets_require_external_exact_path_and_digest(tmp_path):
    target = tmp_path / "skill"
    target.mkdir()
    trusted = tmp_path / "trusted.yml"
    trusted.write_text(
        "trusted_assets:\n"
        "  - path: assets/logo.bin\n"
        f"    sha256: {'a' * 64}\n",
        encoding="utf-8",
    )
    loaded = config.load_config(trusted, target)
    assert loaded.trusted_assets == [
        {"path": "assets/logo.bin", "sha256": "a" * 64}
    ]

    trusted.write_text(
        "trusted_assets:\n"
        "  - path: ../outside.bin\n"
        f"    sha256: {'a' * 64}\n",
        encoding="utf-8",
    )
    with pytest.raises(config.ConfigError, match="safe relative path"):
        config.load_config(trusted, target)


def test_config_subset_does_not_depend_on_pyyaml(tmp_path):
    target = tmp_path / "skill"
    target.mkdir()
    trusted = tmp_path / "trusted.yml"
    trusted.write_text(
        "allow_domains:\n  nested: unsupported\n",
        encoding="utf-8",
    )
    with pytest.raises(config.ConfigError, match="unsupported list structure"):
        config.load_config(trusted, target)


def test_semantic_policy_resolves_environment_and_rejects_url_credentials(monkeypatch):
    monkeypatch.setenv("OPENAI_MODEL", "policy-model")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://provider.example/v1")
    effective = semantic.policy(semantic.Options(mode="api"))
    assert effective["model"] == "policy-model"
    assert effective["base_url"] == "https://provider.example/v1"
    assert effective["effect"] == "advisory"

    with pytest.raises(semantic.SemanticError, match="must not contain credentials"):
        semantic.policy(
            semantic.Options(mode="api", base_url="https://token@provider.example/v1")
        )


def test_lock_pins_effective_semantic_and_scan_policy(tmp_path):
    report = {
        "schema": "skill-auditor-report/v1",
        "version": "0.9.0",
        "scan_status": "COMPLETE",
        "content_hash": "a" * 64,
        "rules_digest": "b" * 64,
        "coverage": {"manifest_entries": 2, "scanned_text": 1},
        "source": {
            "kind": "git",
            "repository": "https://github.com/example/demo",
            "requested_ref": "v1",
            "resolved_commit": "c" * 40,
            "content_hash": "a" * 64,
        },
        "fail_on": "CRITICAL",
        "min_severity": "INFO",
        "semantic": {
            "mode": "api",
            "model": "policy-model",
            "base_url": "https://provider.example/v1",
            "prompt_version": semantic.PROMPT_VERSION,
            "min_confidence": 0.9,
            "effect": "advisory",
        },
        "verdict": "SAFE_TO_INSTALL",
        "full_verdict": "SAFE_TO_INSTALL",
        "all_findings": [],
    }
    payload = integrity.build(report)
    assert payload["semantic"]["effect"] == "advisory"
    assert payload["semantic"]["base_url"] == "https://provider.example/v1"
    assert payload["scan_status"] == "COMPLETE"

    path = tmp_path / "lock.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert integrity.load(path) == payload

    incomplete_lock = dict(payload, scan_status="INCOMPLETE")
    path.write_text(json.dumps(incomplete_lock), encoding="utf-8")
    with pytest.raises(integrity.LockError, match="complete scan"):
        integrity.load(path)

    baseline_payload = baseline.build(report)
    assert baseline_payload["report_schema"] == report["schema"]
    assert baseline_payload["scan_status"] == "COMPLETE"
    assert baseline_payload["source"] == report["source"]
    assert baseline_payload["coverage"] == report["coverage"]
    assert baseline_payload["semantic"] == report["semantic"]

    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(baseline_payload), encoding="utf-8")
    loaded_baseline = baseline.load(baseline_path)
    assert loaded_baseline["source"] == report["source"]
    assert loaded_baseline["baseline_path"] == str(baseline_path.resolve())
