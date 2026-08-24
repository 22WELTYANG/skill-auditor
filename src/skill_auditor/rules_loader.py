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
    "editor-tampering",
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
    "editor-tampering": "Editor and extension tampering",
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
KNOWN_CHECKS = {
    "archive-hidden-executable",
    "archive-link",
    "archive-path-traversal",
    "archive-resource-limit",
    "description-mismatch",
    "filesystem-link-external",
    "filesystem-link-internal",
    "mcp-config-write",
    "node-exfiltration",
    "powershell-download-exec",
    "python-decoded-exec",
    "python-exfiltration",
    "unicode-homoglyph",
    "vscode-remote-vsix-install",
}
VALID_CONFIDENCE = {"", "low", "medium", "high"}
RESERVED_ENGINE_RULE_IDS = frozenset(
    {
        "BOUNDARY-001",
        "BOUNDARY-002",
        "ARCHIVE-001",
        "ARCHIVE-002",
        "ARCHIVE-003",
        "ARCHIVE-004",
    }
)
_UNSAFE_FIELD_RE = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\ud800-\udfff]"
)


class RuleError(ValueError):
    pass


def _parse_scalar(raw: str, line_number: int) -> str:
    value = raw.strip()
    if not value:
        return ""
    if value[0] in "'\"":
        if len(value) < 2 or value[-1] != value[0]:
            raise RuleError(
                f"line {line_number}: quoted rule fields must end at the closing quote"
            )
        if value[0] == "'":
            return value[1:-1].replace("''", "'")
        inner = value[1:-1]
        if "\\" in inner or '"' in inner:
            raise RuleError(
                f"line {line_number}: YAML double-quoted escapes are not supported; use single quotes"
            )
        return inner
    if value[0] in "&*!|>{[":
        raise RuleError(
            f"line {line_number}: YAML tags, anchors, aliases, blocks, and flow values are not supported"
        )
    if " #" in value or ": " in value or value.startswith(("- ", "? ")):
        raise RuleError(
            f"line {line_number}: YAML comments and nested values are not supported; quote literal text"
        )
    return value


def _mini_parse(text: str) -> dict:
    rules: list[dict] = []
    current: dict | None = None
    saw_root = False
    for line_number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "\t" in raw:
            raise RuleError(f"line {line_number}: tabs are not supported")
        if stripped == "rules:" and raw == stripped:
            if saw_root:
                raise RuleError(f"line {line_number}: duplicate rules key")
            saw_root = True
            continue
        if not saw_root:
            raise RuleError(f"line {line_number}: expected top-level rules key")
        item = re.fullmatch(r"  -\s+(.+)", raw)
        if item:
            current = {}
            rules.append(current)
            key_value = re.fullmatch(r"([A-Za-z_][\w-]*):\s*(.*)", item.group(1))
            if not key_value:
                raise RuleError(f"line {line_number}: rule item must start with a field")
            current[key_value.group(1)] = _parse_scalar(
                key_value.group(2), line_number
            )
            continue
        key_value = re.fullmatch(r"    ([A-Za-z_][\w-]*):\s*(.*)", raw)
        if not key_value or current is None:
            raise RuleError(f"line {line_number}: unsupported YAML structure")
        key = key_value.group(1)
        if key in current:
            raise RuleError(f"line {line_number}: duplicate rule field {key!r}")
        current[key] = _parse_scalar(key_value.group(2), line_number)
    if not saw_root:
        raise RuleError("missing top-level rules key")
    return {"rules": rules}


def _load_yaml(text: str) -> dict:
    # The finite parser is canonical on every host.  Optional PyYAML must not
    # broaden the accepted policy language or change scalar types.
    return _mini_parse(text)


def _validate(rule: dict, source: str) -> None:
    rule_id = rule.get("id", "<no id>")
    for field in ("id", "category", "severity", "layer"):
        if not rule.get(field):
            raise RuleError(f"{source}: rule {rule_id} missing required field '{field}'")
    if any(_UNSAFE_FIELD_RE.search(value) for value in rule.values() if isinstance(value, str)):
        raise RuleError(f"{source}: rule {rule_id} contains unsafe control characters")
    if rule["severity"] not in VALID_SEVERITY:
        raise RuleError(f"{source}: rule {rule_id} bad severity {rule['severity']!r}")
    if rule["layer"] not in VALID_LAYER:
        raise RuleError(f"{source}: rule {rule_id} bad layer {rule['layer']!r}")
    if rule.get("check") and rule["check"] not in KNOWN_CHECKS:
        raise RuleError(f"{source}: rule {rule_id} unknown check {rule['check']!r}")
    if rule.get("confidence", "") not in VALID_CONFIDENCE:
        raise RuleError(
            f"{source}: rule {rule_id} bad confidence {rule['confidence']!r}"
        )
    if not re.fullmatch(r"[A-Z][A-Z0-9-]*-[0-9]{3}", rule["id"]):
        raise RuleError(f"{source}: rule id {rule['id']!r} has an invalid format")
    if not rule.get("pattern") and not rule.get("check"):
        raise RuleError(f"{source}: rule {rule_id} needs either 'pattern' or 'check'")
    if rule["layer"] == "semantic" and not rule.get("guidance") and not rule.get("check"):
        raise RuleError(f"{source}: semantic rule {rule_id} should provide guidance")
    if rule.get("pattern"):
        try:
            re.compile(rule["pattern"])
        except re.error as exc:
            raise RuleError(f"{source}: rule {rule_id} regex error: {exc}") from exc


def load_rules(
    rules_dir: Path | str = DEFAULT_RULES_DIR,
    *,
    trusted_engine_catalog: bool = False,
) -> list[dict]:
    directory = Path(rules_dir)
    if not directory.is_dir():
        raise RuleError(f"rules directory not found: {directory}")
    try:
        allow_engine_rules = (
            trusted_engine_catalog
            or directory.resolve(strict=True) == DEFAULT_RULES_DIR.resolve(strict=True)
        )
    except OSError as exc:
        raise RuleError(f"cannot resolve rules directory: {exc}") from exc
    loaded: list[dict] = []
    seen: set[str] = set()
    for path in sorted(directory.glob("*.yaml")):
        try:
            parsed = _load_yaml(path.read_text(encoding="utf-8"))
        except RuleError as exc:
            raise RuleError(f"{path.name}: cannot load rules: {exc}") from exc
        except Exception as exc:
            raise RuleError(f"{path.name}: cannot load rules: {exc}") from exc
        for item in parsed.get("rules") or []:
            if not isinstance(item, dict):
                raise RuleError(f"{path.name}: each rule must be a mapping")
            unknown = set(item) - set(_STRING_KEYS)
            if unknown:
                raise RuleError(
                    f"{path.name}: unsupported rule field(s): "
                    + ", ".join(sorted(unknown))
                )
            if not all(isinstance(value, str) for value in item.values()):
                raise RuleError(f"{path.name}: all rule fields must be strings")
            rule = {key: (item.get(key) or "") for key in _STRING_KEYS}
            rule["layer"] = rule["layer"] or "deterministic"
            rule["_source"] = path.name
            _validate(rule, path.name)
            if not allow_engine_rules and rule["id"] in RESERVED_ENGINE_RULE_IDS:
                raise RuleError(
                    f"{path.name}: rule id {rule['id']} is reserved by the scan engine"
                )
            if allow_engine_rules and rule["id"] in RESERVED_ENGINE_RULE_IDS:
                # This marker is assigned by the trusted loader, never accepted
                # from YAML, so the scanner can distinguish the packaged
                # source-of-truth definition from a caller-constructed mapping.
                rule["_engine_builtin"] = True
            if rule["id"] in seen:
                raise RuleError(f"{path.name}: duplicate rule id {rule['id']}")
            seen.add(rule["id"])
            if rule.get("pattern"):
                rule["_regex"] = re.compile(rule["pattern"])
            loaded.append(rule)
    if not loaded:
        raise RuleError(f"rules directory contains no usable rules: {directory}")
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
