from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "research_corpus.py"
SPEC = importlib.util.spec_from_file_location("research_corpus", SCRIPT)
research = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(research)


def test_wilson_interval_is_bounded_and_nonempty():
    low, high = research.wilson_interval(80, 100)
    assert 0 < low < 0.8 < high < 1
    assert research.wilson_interval(0, 0) == (None, None)


def test_label_sample_is_deterministic_and_stratified():
    findings = [
        {
            "repository": "org/repo",
            "commit": "a" * 40,
            "skill": f"skill-{index}",
            "rule_id": "RULE-A" if index % 2 else "RULE-B",
            "severity": "WARNING",
            "category": "test",
            "fingerprint": f"{index:064x}",
            "artifact_uri": "SKILL.md",
            "line": 1,
            "needs_semantic_review": False,
        }
        for index in range(20)
    ]
    first = research.build_label_sample({"findings": findings}, 10, 0.20)
    second = research.build_label_sample({"findings": findings}, 10, 0.20)
    assert first == second
    assert first["sample_size"] == 10
    assert first["double_review_count"] == 2
    assert {item["rule_id"] for item in first["items"]} == {"RULE-A", "RULE-B"}
