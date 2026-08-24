from __future__ import annotations

import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator

from skill_auditor import cli
from skill_auditor.rules_loader import CRITICAL, INFO, load_rules


ROOT = Path(__file__).resolve().parents[1]
PUBLIC_SCHEMA = ROOT / "schemas" / "skill-auditor-report-v1.schema.json"
PACKAGED_SCHEMA = (
    ROOT / "src" / "skill_auditor" / "schemas" / "skill-auditor-report-v1.schema.json"
)


def test_public_and_packaged_report_schema_are_identical():
    assert PUBLIC_SCHEMA.read_bytes() == PACKAGED_SCHEMA.read_bytes()
    schema = json.loads(PUBLIC_SCHEMA.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["schema"]["const"] == "skill-auditor-report/v1"
    Draft202012Validator.check_schema(schema)


def test_clean_report_satisfies_v1_contract_surface():
    skill = ROOT / "examples" / "clean-skill"
    report = cli.build_report(
        str(skill), skill, load_rules(), min_severity=INFO, fail_on=CRITICAL
    )
    schema = json.loads(PUBLIC_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(report)

    assert set(schema["required"]) <= set(report)
    assert report["schema"] == "skill-auditor-report/v1"
    assert report["scan_status"] in {"COMPLETE", "INCOMPLETE"}
    assert report["source"]["kind"] in {"local", "archive", "git"}
    assert re.fullmatch(r"[0-9a-f]{64}", report["source"]["content_hash"])
    assert report["semantic"]["effect"] in {"advisory", "dismiss"}
    assert report["exit_code"] in {0, 1, 2, 3}
    for finding in report["all_findings"]:
        assert finding["id"] == finding["rule_id"]
        assert finding["explanation"] == finding["rationale"]
        assert finding["recommendation"] == finding["guidance"] or finding["guidance"] == ""


def test_recursive_and_incomplete_reports_validate_against_v1_schema(tmp_path):
    schema = json.loads(PUBLIC_SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    rules = load_rules()

    repo = tmp_path / "repo"
    for name in ("one", "two"):
        skill = repo / name
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Schema fixture.\n---\n",
            encoding="utf-8",
        )
    recursive = cli.build_recursive_report(
        str(repo),
        repo,
        rules,
        min_severity=INFO,
        fail_on=CRITICAL,
        source_root=repo,
        use_cache=False,
    )
    validator.validate(recursive)

    incomplete_skill = tmp_path / "incomplete"
    incomplete_skill.mkdir()
    (incomplete_skill / "SKILL.md").write_text(
        "---\nname: incomplete\ndescription: Schema fixture.\n---\n",
        encoding="utf-8",
    )
    (incomplete_skill / "payload.bin").write_bytes(b"\x00uninspected")
    incomplete = cli.build_report(
        str(incomplete_skill),
        incomplete_skill,
        rules,
        min_severity=INFO,
        fail_on=CRITICAL,
    )
    assert incomplete["scan_status"] == "INCOMPLETE"
    validator.validate(incomplete)
