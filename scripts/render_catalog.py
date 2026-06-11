#!/usr/bin/env python3
"""
render_catalog.py — regenerate references/risk-patterns.md from rules/*.yaml.

The catalog is a build artifact. Rules live only in rules/*.yaml; running this
script renders the human-readable catalog from them, so the catalog and the
scanner can never drift out of sync.

Usage:
    python scripts/render_catalog.py            # write references/risk-patterns.md
    python scripts/render_catalog.py --check     # exit 1 if the file is stale
    python scripts/render_catalog.py --stdout    # print, don't write
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import rules_loader as rl  # noqa: E402

OUTPUT = rl.REPO_ROOT / "references" / "risk-patterns.md"

HEADER = """<!-- AUTO-GENERATED from rules/, do not edit by hand. Run: python scripts/render_catalog.py -->

# Risk Pattern Catalog

This catalog is **generated** from the rule files in [`../rules/`](../rules/) by
[`../scripts/render_catalog.py`](../scripts/render_catalog.py). Do not edit it by
hand — edit the YAML and re-render. The scanner ([`scan.py`](../scripts/scan.py))
loads the same rule files, so the catalog can never drift from what actually runs.

Each rule is one of two layers:

- **deterministic** — a regex match is treated as a real finding.
- **semantic** — the regex only *pre-filters* candidates; the agent judges intent
  during the semantic-review step (see [`../SKILL.md`](../SKILL.md)).

## Severity model

| Severity | Meaning | Effect on verdict |
|---|---|---|
| `CRITICAL` | Almost never legitimate (theft, RCE, hijack). | any → **DO NOT INSTALL** |
| `WARNING` | Risky; legitimate uses exist but need review. | any (no CRITICAL) → **REVIEW** |
| `INFO` | Worth noting; benign alone. | never blocks on its own |
"""

CONTRIBUTE = """## How to contribute a rule

1. Pick a stable `id` prefixed by category (`EXFIL-`, `CRED-`, `SHELL-`,
   `OBFUS-`, `INJECT-`, `MISMATCH-`, `LOGICBOMB-`).
2. Add the rule to the matching file in [`../rules/`](../rules/) using the schema
   in [`../scripts/rules_loader.py`](../scripts/rules_loader.py)
   (`id`, `category`, `severity`, `layer`, `pattern`, `rationale`, `guidance`).
   Single-quote the regex to avoid YAML escaping pain.
3. Re-render this catalog: `python scripts/render_catalog.py`.
4. Test both ways: it should fire on `examples/malicious-skill/` and **not** on
   `examples/clean-skill/`.
5. Open a PR describing the real-world attack it defends against.

**Design rule:** a false positive costs a second look; a false negative costs a
breach. When torn, prefer catching it.
"""


def slug(category: str) -> str:
    return "rules-" + category.replace(" ", "-").replace("/", "")


def render(rules: list[dict]) -> str:
    grouped = rl.group_by_category(rules)
    parts = [HEADER, "\n## Categories\n"]

    # category overview table
    parts.append("| Category | Layer | Rules |")
    parts.append("|---|---|---|")
    for cat, members in grouped:
        layers = sorted({m["layer"] for m in members})
        parts.append(f"| [{rl.CATEGORY_TITLE.get(cat, cat)}](#{slug(cat)}) "
                     f"| {', '.join(layers)} | {len(members)} |")
    parts.append("")

    # per-category sections
    for cat, members in grouped:
        title = rl.CATEGORY_TITLE.get(cat, cat)
        parts.append(f'\n## <a id="{slug(cat)}"></a>{title}\n')
        parts.append(f"Category id: `{cat}`\n")
        for r in members:
            parts.append(f"### `{r['id']}` · {r['severity']} · {r['layer']}")
            if r.get("rationale"):
                parts.append(f"\n{r['rationale']}\n")
            if r.get("check"):
                parts.append(f"- **Check:** built-in `{r['check']}` routine (cross-file).")
            if r.get("pattern"):
                parts.append(f"- **Pattern:** `{r['pattern']}`")
            if r["layer"] == "semantic" and r.get("guidance"):
                parts.append(f"- **Semantic review:** {r['guidance']}")
            parts.append("")

    parts.append(CONTRIBUTE)
    text = "\n".join(parts)
    return text.rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="render_catalog.py")
    ap.add_argument("--rules-dir", default=str(rl.DEFAULT_RULES_DIR))
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the on-disk catalog is out of date")
    ap.add_argument("--stdout", action="store_true", help="print instead of writing")
    args = ap.parse_args(argv)

    try:
        rules = rl.load_rules(args.rules_dir)
    except rl.RuleError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    content = render(rules)

    if args.stdout:
        sys.stdout.reconfigure(encoding="utf-8")
        print(content)
        return 0
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != content:
            print("stale: references/risk-patterns.md differs from rules/. "
                  "Run: python scripts/render_catalog.py", file=sys.stderr)
            return 1
        print("ok: catalog is up to date")
        return 0

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(content, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(rl.REPO_ROOT)} ({len(rules)} rules)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
