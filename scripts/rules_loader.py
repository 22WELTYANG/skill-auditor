#!/usr/bin/env python3
"""
rules_loader.py — single source of truth for skill-auditor's rules.

Rules live as data in ../rules/*.yaml. Both the scanner (scan.py) and the
catalog renderer (render_catalog.py) load them through here, so they can never
drift apart.

Zero-dependency by design: if PyYAML is installed we use it; otherwise we fall
back to a tiny parser that understands the small YAML subset our rule files use
(a top-level `rules:` list of flat string-valued maps). Keep rule files inside
that subset so both paths agree.

Rule schema (per entry):
    id         stable unique id, e.g. EXFIL-001          (required)
    category   one of CATEGORY_ORDER                      (required)
    severity   CRITICAL | WARNING | INFO                  (required)
    layer      deterministic | semantic                   (required)
    pattern    Python `re` regex (single-quoted in YAML)  (required unless `check`)
    rationale  one line: why this is dangerous            (rendered into catalog)
    guidance   hint for the agent's semantic review       (required for semantic)
    check      name of a built-in cross-file routine      (optional; e.g. description-mismatch)
"""

from __future__ import annotations

import re
from pathlib import Path

CRITICAL = "CRITICAL"
WARNING = "WARNING"
INFO = "INFO"
SEVERITY_RANK = {INFO: 0, WARNING: 1, CRITICAL: 2}
VALID_SEVERITY = set(SEVERITY_RANK)
VALID_LAYER = {"deterministic", "semantic"}

# Canonical category order + display titles (used by the catalog + reports).
CATEGORY_ORDER = [
    "data-exfiltration",
    "credential-read",
    "dangerous-shell",
    "obfuscation",
    "prompt-injection",
    "description-mismatch",
    "logic-bomb",
]
CATEGORY_TITLE = {
    "data-exfiltration": "Data exfiltration",
    "credential-read": "Credential read",
    "dangerous-shell": "Dangerous shell",
    "obfuscation": "Obfuscation / evasion",
    "prompt-injection": "Prompt injection / instruction hijack",
    "description-mismatch": "Description vs. behavior mismatch",
    "logic-bomb": "Logic bomb",
}

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES_DIR = REPO_ROOT / "rules"

_STRING_KEYS = ("id", "category", "severity", "layer", "pattern",
                "rationale", "guidance", "check")


# --------------------------------------------------------------------------- #
# YAML loading: PyYAML if available, else a minimal subset parser
# --------------------------------------------------------------------------- #
def _parse_scalar(raw: str) -> str:
    s = raw.strip()
    if not s:
        return ""
    if len(s) >= 2 and s[0] == "'" and s[-1] == "'":
        # YAML single-quoted: backslashes literal, '' -> '
        return s[1:-1].replace("''", "'")
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        return s[1:-1]
    return s


def _mini_parse(text: str) -> dict:
    """Parse the `rules:` list of flat maps. Subset only — see module docstring."""
    rules: list[dict] = []
    cur: dict | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "rules:":
            continue
        item = re.match(r"^(\s*)-\s+(.*)$", line)
        if item:
            cur = {}
            rules.append(cur)
            kv = re.match(r"^([A-Za-z_][\w-]*):\s*(.*)$", item.group(2))
            if kv:
                cur[kv.group(1)] = _parse_scalar(kv.group(2))
            continue
        kv = re.match(r"^\s+([A-Za-z_][\w-]*):\s*(.*)$", line)
        if kv and cur is not None:
            cur[kv.group(1)] = _parse_scalar(kv.group(2))
    return {"rules": rules}


def _load_yaml(text: str) -> dict:
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {"rules": data or []}
    except ImportError:
        return _mini_parse(text)


# --------------------------------------------------------------------------- #
# Rule loading + validation
# --------------------------------------------------------------------------- #
class RuleError(ValueError):
    pass


def _validate(rule: dict, source: str) -> None:
    rid = rule.get("id", "<no id>")
    for field in ("id", "category", "severity", "layer"):
        if not rule.get(field):
            raise RuleError(f"{source}: rule {rid} missing required field '{field}'")
    if rule["severity"] not in VALID_SEVERITY:
        raise RuleError(f"{source}: rule {rid} bad severity {rule['severity']!r}")
    if rule["layer"] not in VALID_LAYER:
        raise RuleError(f"{source}: rule {rid} bad layer {rule['layer']!r}")
    if not rule.get("pattern") and not rule.get("check"):
        raise RuleError(f"{source}: rule {rid} needs either 'pattern' or 'check'")
    if rule["layer"] == "semantic" and not rule.get("guidance") and not rule.get("check"):
        raise RuleError(f"{source}: semantic rule {rid} should provide 'guidance'")
    if rule.get("pattern"):
        try:
            re.compile(rule["pattern"])
        except re.error as e:
            raise RuleError(f"{source}: rule {rid} regex error: {e}") from e


def load_rules(rules_dir: Path | str = DEFAULT_RULES_DIR) -> list[dict]:
    """Load and validate every rule under rules_dir, sorted by category then id."""
    rules_dir = Path(rules_dir)
    if not rules_dir.is_dir():
        raise RuleError(f"rules directory not found: {rules_dir}")
    loaded: list[dict] = []
    seen: set[str] = set()
    for path in sorted(rules_dir.glob("*.yaml")):
        parsed = _load_yaml(path.read_text(encoding="utf-8"))
        for item in parsed.get("rules") or []:
            rule = {k: (item.get(k) or "") for k in _STRING_KEYS}
            rule["layer"] = rule["layer"] or "deterministic"
            rule["_source"] = path.name
            _validate(rule, path.name)
            if rule["id"] in seen:
                raise RuleError(f"{path.name}: duplicate rule id {rule['id']}")
            seen.add(rule["id"])
            if rule.get("pattern"):
                rule["_regex"] = re.compile(rule["pattern"])
            loaded.append(rule)
    loaded.sort(key=lambda r: (_cat_index(r["category"]), r["id"]))
    return loaded


def _cat_index(category: str) -> int:
    return CATEGORY_ORDER.index(category) if category in CATEGORY_ORDER else len(CATEGORY_ORDER)


def group_by_category(rules: list[dict]) -> list[tuple[str, list[dict]]]:
    """Return [(category, [rules...])] in canonical order, only non-empty groups."""
    out = []
    for cat in CATEGORY_ORDER:
        members = [r for r in rules if r["category"] == cat]
        if members:
            out.append((cat, members))
    # any categories not in CATEGORY_ORDER, appended at the end
    extras = sorted({r["category"] for r in rules} - set(CATEGORY_ORDER))
    for cat in extras:
        out.append((cat, [r for r in rules if r["category"] == cat]))
    return out
