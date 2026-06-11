#!/usr/bin/env python3
"""
config.py — false-positive control for skill-auditor.

Three layers of "this hit is OK", applied *before* a report is rendered or a
verdict computed. Nothing is silently dropped: a suppressed finding keeps
`suppressed: true` + a reason and is still listed under `--verbose`.

  1. Built-in domain allowlist
     Package registries and common installer hosts. A *network* finding
     (data-exfiltration) whose line only touches allowlisted hosts is
     suppressed, so a legitimate `pip`/`npm`/`cargo` fetch isn't flagged.

  2. Project config `.skill-auditor.yml`  (read from the scanned skill root)
       allow_domains: [internal.example.com, ...]   # appended to the built-in list
       suppress:                                     # rule+path suppressions
         - rule: EXFIL-001
           path: scripts/legit.sh
       ignore_paths: ["tests/fixtures/**"]           # globs, skipped entirely

  3. Inline suppression
     A source line carrying `# skill-auditor: ignore RULE-ID[,RULE-ID...]`
     (or a bare `# skill-auditor: ignore` for every rule on that line)
     suppresses matches on that line.

This module is dependency-free: it reuses rules_loader's tiny YAML fallback when
PyYAML is absent.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

try:  # reuse the same YAML strategy as the rule loader
    import yaml  # type: ignore

    def _load_yaml(text: str):
        return yaml.safe_load(text)
except ImportError:  # pragma: no cover - exercised only without PyYAML
    yaml = None

    def _load_yaml(text: str):
        return _mini_yaml(text)


CONFIG_FILENAMES = (".skill-auditor.yml", ".skill-auditor.yaml")

# Hosts that legitimate dependency installs talk to. A data-exfiltration hit
# whose line only references these is treated as a benign fetch/publish.
BUILTIN_ALLOW_DOMAINS = (
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "npmjs.com",
    "github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "codeload.github.com",
    "crates.io",
    "static.crates.io",
    "rubygems.org",
    "pkg.go.dev",
    "proxy.golang.org",
    "repo.maven.apache.org",
    "repo1.maven.org",
    "deb.debian.org",
    "archive.ubuntu.com",
)

# Categories whose findings are "did it phone home" — the only ones a domain
# allowlist may clear. Pipe-remote-to-shell (dangerous-shell) is *not* here:
# executing remote code is dangerous regardless of how trusted the host looks.
_ALLOWLISTABLE_CATEGORIES = {"data-exfiltration"}

_DOMAIN_RE = re.compile(r"https?://([^/\s'\"]+)", re.IGNORECASE)
_INLINE_RE = re.compile(r"#\s*skill-auditor:\s*ignore\b([^\n]*)", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Minimal YAML (only what .skill-auditor.yml needs: maps, lists, scalars)
# --------------------------------------------------------------------------- #
def _scalar(raw: str):
    s = raw.strip()
    if (len(s) >= 2) and ((s[0] == s[-1] == "'") or (s[0] == s[-1] == '"')):
        return s[1:-1]
    # inline flow list:  [a, b, c]
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        if not inner:
            return []
        return [_scalar(x) for x in inner.split(",")]
    return s


def _mini_yaml(text: str):
    """Tiny parser for the config subset. Good enough for allow_domains /
    ignore_paths (lists) and suppress (list of {rule, path})."""
    root: dict = {}
    stack = [(-1, root)]  # (indent, container)
    pending_list_item: dict | None = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()

        while stack and indent <= stack[-1][0] and len(stack) > 1:
            stack.pop()
        container = stack[-1][1]

        if line.startswith("- "):
            item = line[2:].strip()
            kv = re.match(r"^([A-Za-z_][\w-]*):\s*(.*)$", item)
            if isinstance(container, list):
                if kv:
                    d = {kv.group(1): _scalar(kv.group(2))}
                    container.append(d)
                    pending_list_item = d
                else:
                    container.append(_scalar(item))
                    pending_list_item = None
            continue

        m = re.match(r"^([A-Za-z_][\w-]*):\s*(.*)$", line)
        if not m:
            # continuation key of the current list item (e.g. path: under - rule:)
            continue
        key, val = m.group(1), m.group(2).strip()
        target = container
        # a key directly following a "- rule:" belongs to that dict item
        if (
            isinstance(container, list)
            and pending_list_item is not None
            and indent > stack[-1][0]
        ):
            target = pending_list_item
        if val == "":
            child: list | dict = []  # assume list; promoted to dict if a key appears
            if isinstance(target, dict):
                target[key] = child
            stack.append((indent, child))
        else:
            if isinstance(target, dict):
                target[key] = _scalar(val)
    return root


# --------------------------------------------------------------------------- #
# Config object
# --------------------------------------------------------------------------- #
class Config:
    def __init__(
        self,
        allow_domains: list[str] | None = None,
        suppress: list[dict] | None = None,
        ignore_paths: list[str] | None = None,
        source: str | None = None,
    ) -> None:
        self.allow_domains = set(BUILTIN_ALLOW_DOMAINS) | {
            d.lower() for d in (allow_domains or [])
        }
        self.extra_allow_domains = [d.lower() for d in (allow_domains or [])]
        self.suppress = suppress or []
        self.ignore_paths = ignore_paths or []
        self.source = source  # path the config was read from, or None

    # -- file/path level ---------------------------------------------------- #
    def is_ignored_path(self, rel_path: str) -> bool:
        rel = rel_path.replace("\\", "/")
        return any(_glob(rel, pat) for pat in self.ignore_paths)

    # -- per-finding suppression ------------------------------------------- #
    def suppression_reason(self, finding: dict, line_text: str) -> str | None:
        """Return a human reason if this finding is suppressed, else None."""
        rid = finding.get("rule_id", "")
        rel = finding.get("file", "").replace("\\", "/")

        # 1. inline comment on the matched line
        inline = _inline_ignore_ids(line_text)
        if inline is not None and (inline == set() or rid in inline):
            return "inline `# skill-auditor: ignore` comment"

        # 2. .skill-auditor.yml suppress: [{rule, path}]
        for entry in self.suppress:
            erule = (entry.get("rule") or "").strip()
            epath = (entry.get("path") or "").strip().replace("\\", "/")
            if erule and erule != rid:
                continue
            if epath and not (rel == epath or _glob(rel, epath)):
                continue
            if erule or epath:
                return f"suppressed by {self.source or '.skill-auditor.yml'}"

        # 3. built-in / configured domain allowlist (network findings only)
        if finding.get("category") in _ALLOWLISTABLE_CATEGORIES:
            hosts = _hosts_in(line_text)
            if hosts and all(self._host_allowed(h) for h in hosts):
                shown = ", ".join(sorted(hosts))
                return f"allowlisted host(s): {shown}"
        return None

    def _host_allowed(self, host: str) -> bool:
        host = host.lower().split("@")[-1].split(":")[0]
        return any(host == d or host.endswith("." + d) for d in self.allow_domains)


def _glob(path: str, pattern: str) -> bool:
    pattern = pattern.replace("\\", "/")
    # fnmatch's * doesn't cross '/'; emulate ** by also trying a flattened match
    if fnmatch.fnmatch(path, pattern):
        return True
    if "**" in pattern:
        collapsed = pattern.replace("**/", "*/").replace("**", "*")
        return fnmatch.fnmatch(path, collapsed) or fnmatch.fnmatch(
            path, pattern.replace("**", "")
        )
    return False


def _hosts_in(line: str) -> set[str]:
    out = set()
    for m in _DOMAIN_RE.finditer(line):
        host = m.group(1).split("@")[-1].split(":")[0].lower()
        out.add(host)
    return out


def _inline_ignore_ids(line: str) -> set[str] | None:
    """None  -> no inline directive on this line.
    set()    -> bare `ignore` (suppress every rule on the line).
    {ids...} -> suppress only those rule ids."""
    m = _INLINE_RE.search(line)
    if not m:
        return None
    rest = m.group(1).strip()
    if not rest:
        return set()
    ids = {tok.strip().upper() for tok in re.split(r"[,\s]+", rest) if tok.strip()}
    return ids


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def load_config(root: Path) -> Config:
    """Load `.skill-auditor.yml` from the scanned skill root, if present."""
    for name in CONFIG_FILENAMES:
        path = root / name
        if path.is_file():
            try:
                data = _load_yaml(path.read_text(encoding="utf-8")) or {}
            except Exception:  # malformed config must never crash a scan
                data = {}
            if not isinstance(data, dict):
                data = {}
            return Config(
                allow_domains=_as_list(data.get("allow_domains")),
                suppress=_as_suppress(data.get("suppress")),
                ignore_paths=_as_list(data.get("ignore_paths")),
                source=name,
            )
    return Config()


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [str(x) for x in v]
    return []


def _as_suppress(v) -> list[dict]:
    out: list[dict] = []
    if isinstance(v, list):
        for item in v:
            if isinstance(item, dict):
                out.append({k: str(val) for k, val in item.items()})
    return out
