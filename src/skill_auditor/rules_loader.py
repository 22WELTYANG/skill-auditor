"""Rule loading and validation."""

from __future__ import annotations

import re
from pathlib import Path

CRITICAL = "CRITICAL"
WARNING = "WARNING"
INFO = "INFO"
SEVERITY_RANK = {INFO: 0, WARNING: 1, CRITICAL: 2}
VALID_SEVERITY = set(SEVERITY_RANK)
VALID_LAYER = {"deterministic", "semantic"}

CATEGORY_ORDER = [
    "filesystem-boundary",
    "data-exfiltration",
    "credential-read",
    "dangerous-shell",
    "powershell",
    "dynamic-execution",
    "archive-risk",
    "git-hook",
    "mcp-tampering",
    "obfuscation",
    "prompt-injection",
    "description-mismatch",
    "logic-bomb",
]
CATEGORY_TITLE = {
    "filesystem-boundary": "Filesystem boundary",
    "data-exfiltration": "Data exfiltration",
    "credential-read": "Credential read",
    "dangerous-shell": "Dangerous shell",
    "powershell": "PowerShell execution",
    "dynamic-execution": "Dynamic execution",
    "archive-risk": "Archive risk",
    "git-hook": "Git hook persistence",
    "mcp-tampering": "MCP configuration tampering",
    "obfuscation": "Obfuscation / evasion",
    "prompt-injection": "Prompt injection / instruction hijack",
    "description-mismatch": "Description vs. behavior mismatch",
    "logic-bomb": "Logic bomb",
}

PACKAGE_ROOT = Path(__file__).resolve().parent
DEFAULT_RULES_DIR = PACKAGE_ROOT / "rules"
_STRING_KEYS = (
    "id", "category", "severity", "layer", "pattern", "rationale",
    "guidance", "check", "files", "confidence",
)


class RuleError(ValueError):
    pass


def _parse_scalar(raw: str) -> str:
    value = raw.strip()
    if not value:
        return ""
    if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
        return value[1:-1].replace("''", "'")
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def _mini_parse(text: str) -> dict:
    rules: list[dict] = []
    current: dict | None = None
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or stripped == "rules:":
            continue
        item = re.match(r"^\s*-\s+(.*)$", raw)
        if item:
            current = {}
            rules.append(current)
            key_value = re.match(r"^([A-Za-z_][\w-]*):\s*(.*)$", item.group(1))
            if key_value:
                current[key_value.group(1)] = _parse_scalar(key_value.group(2))
            continue
        key_value = re.match(r"^\s+([A-Za-z_][\w-]*):\s*(.*)$", raw)
        if key_value and current is not None:
            current[key_value.group(1)] = _parse_scalar(key_value.group(2))
    return {"rules": rules}


def _load_yaml(text: str) -> dict:
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {"rules": data or []}
    except ImportError:
        return _mini_parse(text)


def _validate(rule: dict, source: str) -> None:
    rule_id = rule.get("id", "<no id>")
    for field in ("id", "category", "severity", "layer"):
        if not rule.get(field):
            raise RuleError(f"{source}: rule {rule_id} missing required field '{field}'")
    if rule["severity"] not in VALID_SEVERITY:
        raise RuleError(f"{source}: rule {rule_id} bad severity {rule['severity']!r}")
    if rule["layer"] not in VALID_LAYER:
        raise RuleError(f"{source}: rule {rule_id} bad layer {rule['layer']!r}")
    if not rule.get("pattern") and not rule.get("check"):
        raise RuleError(f"{source}: rule {rule_id} needs either 'pattern' or 'check'")
    if rule["layer"] == "semantic" and not rule.get("guidance") and not rule.get("check"):
        raise RuleError(f"{source}: semantic rule {rule_id} should provide guidance")
    if rule.get("pattern"):
        try:
            re.compile(rule["pattern"])
        except re.error as exc:
            raise RuleError(f"{source}: rule {rule_id} regex error: {exc}") from exc


def load_rules(rules_dir: Path | str = DEFAULT_RULES_DIR) -> list[dict]:
    directory = Path(rules_dir)
    if not directory.is_dir():
        raise RuleError(f"rules directory not found: {directory}")
    loaded: list[dict] = []
    seen: set[str] = set()
    for path in sorted(directory.glob("*.yaml")):
        try:
            parsed = _load_yaml(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise RuleError(f"{path.name}: cannot load rules: {exc}") from exc
        for item in parsed.get("rules") or []:
            if not isinstance(item, dict):
                raise RuleError(f"{path.name}: each rule must be a mapping")
            rule = {key: (item.get(key) or "") for key in _STRING_KEYS}
            rule["layer"] = rule["layer"] or "deterministic"
            rule["_source"] = path.name
            _validate(rule, path.name)
            if rule["id"] in seen:
                raise RuleError(f"{path.name}: duplicate rule id {rule['id']}")
            seen.add(rule["id"])
            if rule.get("pattern"):
                rule["_regex"] = re.compile(rule["pattern"])
            loaded.append(rule)
    loaded.sort(key=lambda rule: (_cat_index(rule["category"]), rule["id"]))
    return loaded


def rule_applies_to_file(rule: dict, relative_path: str) -> bool:
    patterns = [item.strip() for item in rule.get("files", "").split(",") if item.strip()]
    if not patterns:
        return True
    from fnmatch import fnmatch
    normalized = relative_path.replace("\\", "/").lower()
    return any(fnmatch(normalized, pattern.lower()) for pattern in patterns)


def _cat_index(category: str) -> int:
    return CATEGORY_ORDER.index(category) if category in CATEGORY_ORDER else len(CATEGORY_ORDER)


def group_by_category(rules: list[dict]) -> list[tuple[str, list[dict]]]:
    output = []
    for category in CATEGORY_ORDER:
        members = [rule for rule in rules if rule["category"] == category]
        if members:
            output.append((category, members))
    extras = sorted({rule["category"] for rule in rules} - set(CATEGORY_ORDER))
    for category in extras:
        output.append((category, [rule for rule in rules if rule["category"] == category]))
    return output
