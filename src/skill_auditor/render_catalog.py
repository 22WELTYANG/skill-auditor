"""Generate the human-readable rule catalog."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import rules_loader as rl

SOURCE_ROOT = Path(__file__).resolve().parents[2]
OUTPUT = SOURCE_ROOT / "references" / "risk-patterns.md"

HEADER = """<!-- AUTO-GENERATED from rules/, do not edit by hand. Run: python scripts/render_catalog.py -->

# Risk Pattern Catalog

This catalog is generated from the packaged rule catalog. Rules are either
deterministic matches or semantic pre-filters that require contextual review.

## Severity model

| Severity | Meaning | Effect on verdict |
|---|---|---|
| `CRITICAL` | Strong evidence of theft, execution, escape, or hijack. | any -> **DO NOT INSTALL** |
| `WARNING` | Risky behavior that requires review. | any (no CRITICAL) -> **REVIEW** |
| `INFO` | Context worth surfacing. | does not block by default |
"""


def render(rules: list[dict]) -> str:
    parts = [HEADER, "\n## Categories\n", "| Category | Layer | Rules |", "|---|---|---:|"]
    grouped = rl.group_by_category(rules)
    for category, members in grouped:
        layers = ", ".join(sorted({member["layer"] for member in members}))
        parts.append(f"| {rl.CATEGORY_TITLE.get(category, category)} | {layers} | {len(members)} |")
    for category, members in grouped:
        parts.append(f"\n## {rl.CATEGORY_TITLE.get(category, category)}\n")
        parts.append(f"Category id: `{category}`\n")
        for rule in members:
            parts.append(f"### `{rule['id']}` · {rule['severity']} · {rule['layer']}")
            parts.append(f"\n{rule.get('rationale', '')}\n")
            if rule.get("files"):
                parts.append(f"- **Files:** `{rule['files']}`")
            if rule.get("check"):
                parts.append(f"- **Check:** `{rule['check']}`")
            if rule.get("pattern"):
                parts.append(f"- **Pattern:** `{rule['pattern']}`")
            if rule.get("guidance"):
                parts.append(f"- **Review:** {rule['guidance']}")
            parts.append("")
    return "\n".join(parts).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules-dir", default=None)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--stdout", action="store_true")
    args = parser.parse_args(argv)
    rules = rl.load_rules(args.rules_dir) if args.rules_dir else rl.load_rules()
    content = render(rules)
    if args.stdout:
        print(content)
        return 0
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != content:
            print("stale: references/risk-patterns.md", file=sys.stderr)
            return 1
        print("ok: catalog is up to date")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(content, encoding="utf-8")
    print(f"wrote {OUTPUT}")
    return 0

