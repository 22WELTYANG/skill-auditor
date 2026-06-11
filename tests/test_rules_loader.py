"""Guard: the zero-dependency YAML fallback must agree with PyYAML.

Rule files are constrained to single-line scalars so that `_mini_parse`
can load them without PyYAML. If a rule ever uses YAML the fallback
cannot represent (multi-line strings, nested mappings), this test fails
instead of the fallback silently dropping fields at scan time.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from skill_auditor.rules_loader import _STRING_KEYS, _mini_parse

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


def test_mini_parse_matches_pyyaml_for_every_rule_file():
    rule_files = sorted(RULES_DIR.glob("*.yaml"))
    assert rule_files, f"no rule files found under {RULES_DIR}"
    for path in rule_files:
        text = path.read_text(encoding="utf-8")
        expected = yaml.safe_load(text)["rules"]
        actual = _mini_parse(text)["rules"]
        assert len(actual) == len(expected), f"{path.name}: rule count diverges"
        for index, (mini, full) in enumerate(zip(actual, expected)):
            for key in _STRING_KEYS:
                mini_value = mini.get(key) or ""
                full_value = str(full.get(key) or "")
                assert mini_value == full_value, (
                    f"{path.name}: rule #{index} field {key!r} diverges: "
                    f"fallback={mini_value!r} pyyaml={full_value!r}"
                )
