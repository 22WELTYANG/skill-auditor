"""Trusted, external false-positive configuration."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

try:
    import yaml  # type: ignore

    def _load_yaml(text: str):
        return yaml.safe_load(text)
except ImportError:  # pragma: no cover
    yaml = None

    def _load_yaml(text: str):
        return _mini_yaml(text)


CONFIG_FILENAMES = (".skill-auditor.yml", ".skill-auditor.yaml")
_DOMAIN_RE = re.compile(r"https?://([^/\s'\"]+)", re.IGNORECASE)
_ALLOWLISTABLE_RULES = {"EXFIL-001"}


class ConfigError(ValueError):
    pass


def _scalar(raw: str):
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        return [] if not inner else [_scalar(item) for item in inner.split(",")]
    return value


def _mini_yaml(text: str):
    root: dict = {}
    current_key = ""
    current_item: dict | None = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        line = raw.strip()
        if line.startswith("- "):
            value = line[2:].strip()
            container = root.setdefault(current_key, [])
            match = re.match(r"^([A-Za-z_][\w-]*):\s*(.*)$", value)
            if match and isinstance(container, list):
                current_item = {match.group(1): _scalar(match.group(2))}
                container.append(current_item)
            elif isinstance(container, list):
                container.append(_scalar(value))
                current_item = None
            continue
        match = re.match(r"^([A-Za-z_][\w-]*):\s*(.*)$", line)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip()
        if raw.startswith((" ", "\t")) and current_item is not None:
            current_item[key] = _scalar(value)
        elif value:
            root[key] = _scalar(value)
            current_key = key
            current_item = None
        else:
            root[key] = []
            current_key = key
            current_item = None
    return root


class Config:
    def __init__(
        self,
        allow_domains: list[str] | None = None,
        suppress: list[dict] | None = None,
        ignore_paths: list[str] | None = None,
        source: str | None = None,
    ) -> None:
        self.allow_domains = {domain.lower() for domain in (allow_domains or [])}
        self.suppress = suppress or []
        self.ignore_paths = ignore_paths or []
        self.source = source

    def is_ignored_path(self, relative_path: str) -> bool:
        relative = relative_path.replace("\\", "/")
        return any(_glob(relative, pattern) for pattern in self.ignore_paths)

    def suppression_reason(self, finding: dict, line_text: str) -> str | None:
        rule_id = finding.get("rule_id", "")
        relative = finding.get("file", "").replace("\\", "/")

        for entry in self.suppress:
            entry_rule = (entry.get("rule") or "").strip()
            entry_path = (entry.get("path") or "").strip().replace("\\", "/")
            if entry_rule and entry_rule != rule_id:
                continue
            if entry_path and not (relative == entry_path or _glob(relative, entry_path)):
                continue
            if entry_rule or entry_path:
                return f"suppressed by trusted config {self.source}"

        if rule_id in _ALLOWLISTABLE_RULES and self.allow_domains:
            hosts = _hosts_in(line_text)
            if hosts and all(self._host_allowed(host) for host in hosts):
                return "allowlisted by trusted config: " + ", ".join(sorted(hosts))
        return None

    def _host_allowed(self, host: str) -> bool:
        clean = host.lower().split("@")[-1].split(":")[0]
        return any(clean == domain or clean.endswith("." + domain)
                   for domain in self.allow_domains)


def _glob(path: str, pattern: str) -> bool:
    pattern = pattern.replace("\\", "/")
    if fnmatch.fnmatch(path, pattern):
        return True
    if "**" in pattern:
        return fnmatch.fnmatch(path, pattern.replace("**/", "*/").replace("**", "*"))
    return False


def _hosts_in(line: str) -> set[str]:
    return {
        match.group(1).split("@")[-1].split(":")[0].lower()
        for match in _DOMAIN_RE.finditer(line)
    }


def target_config_files(root: Path) -> list[str]:
    return [name for name in CONFIG_FILENAMES if (root / name).is_file()]


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def load_config(config_path: str | Path | None, target_root: Path) -> Config:
    if config_path is None:
        return Config()
    candidate = Path(config_path).expanduser()
    try:
        if candidate.is_symlink():
            raise ConfigError("trusted config must not be a symlink")
        resolved = candidate.resolve(strict=True)
        target = target_root.resolve(strict=True)
    except OSError as exc:
        raise ConfigError(f"cannot resolve trusted config: {candidate}: {exc}") from exc
    if _is_within(resolved, target):
        raise ConfigError("trusted config must be outside the scanned target")
    if not resolved.is_file():
        raise ConfigError("trusted config must be a regular file")
    try:
        data = _load_yaml(resolved.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        raise ConfigError(f"cannot read trusted config: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError("trusted config must contain a YAML mapping")
    return Config(
        allow_domains=_as_list(data.get("allow_domains")),
        suppress=_as_suppress(data.get("suppress")),
        ignore_paths=_as_list(data.get("ignore_paths")),
        source=str(resolved),
    )


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    raise ConfigError("allow_domains and ignore_paths must be lists")


def _as_suppress(value) -> list[dict]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ConfigError("suppress must be a list")
    output = []
    for item in value:
        if not isinstance(item, dict):
            raise ConfigError("each suppress entry must be a mapping")
        output.append({key: str(entry_value) for key, entry_value in item.items()})
    return output
