"""Trusted, external false-positive configuration."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from pathlib import PurePosixPath

CONFIG_FILENAMES = (".skill-auditor.yml", ".skill-auditor.yaml")
_DOMAIN_RE = re.compile(r"https?://([^/\s'\"]+)", re.IGNORECASE)
_ALLOWLISTABLE_RULES = {"EXFIL-001"}
_TOP_LEVEL_KEYS = {"allow_domains", "suppress", "ignore_paths", "trusted_assets"}
_BIDI_AND_CONTROL_RE = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\ud800-\udfff]"
)
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


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
    """Parse the deliberately small, dependency-free trusted-config subset.

    This parser is canonical even when PyYAML is installed.  Unsupported YAML
    is rejected so policy does not change with the host environment.
    """
    root: dict = {}
    current_key = ""
    current_item: dict | None = None
    for line_number, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if "\t" in raw:
            raise ConfigError(f"line {line_number}: tabs are not supported")
        if re.search(r"(?:^[- ]*|:\s*)[&*!|>]", raw):
            raise ConfigError(
                f"line {line_number}: unsupported YAML feature in trusted config"
            )
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if indent == 0:
            match = re.fullmatch(r"([A-Za-z_][\w-]*):\s*(.*)", line)
            if not match:
                raise ConfigError(f"line {line_number}: expected a top-level key")
            key, value = match.group(1), match.group(2).strip()
            if key not in _TOP_LEVEL_KEYS:
                raise ConfigError(f"line {line_number}: unknown config key {key!r}")
            if key in root:
                raise ConfigError(f"line {line_number}: duplicate config key {key!r}")
            if value:
                parsed = _scalar(value)
                if not isinstance(parsed, list):
                    raise ConfigError(
                        f"line {line_number}: {key} must be a list"
                    )
                root[key] = parsed
            else:
                root[key] = []
            current_key = key
            current_item = None
            continue
        if not current_key:
            raise ConfigError(f"line {line_number}: list item has no parent key")
        if indent < 2:
            raise ConfigError(f"line {line_number}: invalid indentation")
        if line.startswith("- "):
            value = line[2:].strip()
            if not value:
                raise ConfigError(f"line {line_number}: empty list item")
            container = root[current_key]
            match = re.fullmatch(r"([A-Za-z_][\w-]*):\s*(.*)", value)
            if match and isinstance(container, list):
                current_item = {match.group(1): _scalar(match.group(2))}
                container.append(current_item)
            elif isinstance(container, list):
                container.append(_scalar(value))
                current_item = None
            continue
        match = re.fullmatch(r"([A-Za-z_][\w-]*):\s*(.*)", line)
        if not match or current_item is None or indent < 4:
            raise ConfigError(f"line {line_number}: unsupported list structure")
        key, value = match.group(1), match.group(2).strip()
        if key in current_item:
            raise ConfigError(f"line {line_number}: duplicate entry field {key!r}")
        current_item[key] = _scalar(value)
    return root


def _load_yaml(text: str):
    return _mini_yaml(text)


class Config:
    def __init__(
        self,
        allow_domains: list[str] | None = None,
        suppress: list[dict] | None = None,
        ignore_paths: list[str] | None = None,
        trusted_assets: list[dict] | None = None,
        source: str | None = None,
    ) -> None:
        self.allow_domains = {domain.lower() for domain in (allow_domains or [])}
        self.suppress = suppress or []
        self.ignore_paths = ignore_paths or []
        self.trusted_assets = trusted_assets or []
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
        trusted_assets=_as_trusted_assets(data.get("trusted_assets")),
        source=str(resolved),
    )


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        if not all(isinstance(item, str) for item in value):
            raise ConfigError("allow_domains and ignore_paths entries must be strings")
        return value
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
        unknown = set(item) - {"rule", "path"}
        if unknown:
            raise ConfigError("suppress entries only support rule and path")
        if not all(isinstance(entry_value, str) for entry_value in item.values()):
            raise ConfigError("suppress rule and path must be strings")
        normalized = {key: entry_value for key, entry_value in item.items()}
        if not normalized.get("rule") and not normalized.get("path"):
            raise ConfigError("each suppress entry needs rule or path")
        output.append(normalized)
    return output


def _as_trusted_assets(value) -> list[dict]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ConfigError("trusted_assets must be a list")
    output: list[dict] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            raise ConfigError("each trusted_assets entry must be a mapping")
        if set(item) != {"path", "sha256"}:
            raise ConfigError("trusted_assets entries require exactly path and sha256")
        path = item.get("path")
        digest = item.get("sha256")
        if not isinstance(path, str) or not isinstance(digest, str):
            raise ConfigError("trusted asset path and sha256 must be strings")
        normalized = path.replace("\\", "/").strip()
        pure = PurePosixPath(normalized)
        if (
            not normalized
            or pure.is_absolute()
            or normalized.startswith("/")
            or re.match(r"^[A-Za-z]:", normalized)
            or any(part in {"", ".", ".."} for part in pure.parts)
            or any(
                ":" in part
                or part.endswith((" ", "."))
                or part.split(".", 1)[0].upper() in _WINDOWS_RESERVED
                for part in pure.parts
            )
            or _BIDI_AND_CONTROL_RE.search(normalized)
        ):
            raise ConfigError("trusted asset path must be a safe relative path")
        if not _SHA256_RE.fullmatch(digest):
            raise ConfigError("trusted asset sha256 must contain 64 hexadecimal characters")
        normalized = pure.as_posix()
        if normalized in seen:
            raise ConfigError(f"duplicate trusted asset path: {normalized}")
        seen.add(normalized)
        output.append({"path": normalized, "sha256": digest.lower()})
    return output
