"""Deterministic scanning primitives for captured skill snapshots."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

from . import analyzers, archives, config as cfg, manifest as manifest_mod, models, paths
from .errors import ScanError
from .rules_loader import (
    CRITICAL,
    RESERVED_ENGINE_RULE_IDS,
    SEVERITY_RANK,
    WARNING,
    rule_applies_to_file,
)

CONTEXT_LINES = 3
_MISMATCH_TRIGGER_CATS = {
    "data-exfiltration", "credential-read", "dangerous-shell", "obfuscation",
    "powershell", "dynamic-execution", "mcp-tampering",
}
_MISMATCH_SENSITIVE_TERMS = (
    "secret", "credential", "password", "token", "ssh", "aws", "exfiltrat",
    "upload your", "send your", "steal", "private key", "delete", "rm -rf",
    "network", "remote server", "powershell", "mcp",
)
_ENGINE_RULES = {
    "BOUNDARY-001": {
        "id": "BOUNDARY-001", "category": "filesystem-boundary",
        "severity": CRITICAL, "layer": "deterministic",
        "rationale": "A filesystem link escapes the skill root, is broken, or forms a cycle.",
        "guidance": "Remove the link before installation.",
    },
    "BOUNDARY-002": {
        "id": "BOUNDARY-002", "category": "filesystem-boundary",
        "severity": WARNING, "layer": "deterministic",
        "rationale": "The skill contains an internal filesystem link that is not followed.",
        "guidance": "Replace the link with reviewed regular files before installation.",
    },
    "ARCHIVE-001": {
        "id": "ARCHIVE-001", "category": "archive-risk",
        "severity": CRITICAL, "layer": "deterministic",
        "rationale": "An archive member escapes its extraction root.", "guidance": "",
    },
    "ARCHIVE-002": {
        "id": "ARCHIVE-002", "category": "archive-risk",
        "severity": CRITICAL, "layer": "deterministic",
        "rationale": "An archive contains a symbolic or hard link.", "guidance": "",
    },
    "ARCHIVE-003": {
        "id": "ARCHIVE-003", "category": "archive-risk",
        "severity": WARNING, "layer": "deterministic",
        "rationale": "An archive contains a hidden executable or hook.", "guidance": "",
    },
    "ARCHIVE-004": {
        "id": "ARCHIVE-004", "category": "archive-risk",
        "severity": WARNING, "layer": "deterministic",
        "rationale": "An archive exceeds a safe inspection resource boundary.", "guidance": "",
    },
}
assert frozenset(_ENGINE_RULES) == RESERVED_ENGINE_RULE_IDS


def parse_frontmatter(text: str) -> tuple[dict[str, str], int]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise ScanError("SKILL.md must start with YAML frontmatter")
    closing = next((index for index, line in enumerate(lines[1:], start=1)
                    if line.strip() == "---"), None)
    if closing is None:
        raise ScanError("SKILL.md frontmatter is not closed")
    output: dict[str, str] = {}
    key: str | None = None
    buffer: list[str] = []
    description_line = 0
    for line_number, line in enumerate(lines[1:closing], start=2):
        match = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if match and not line.startswith((" ", "\t")):
            if key is not None:
                output[key] = _frontmatter_value(buffer)
            key = match.group(1).lower()
            buffer = [match.group(2)]
            if key == "description":
                description_line = line_number
        elif key is not None:
            buffer.append(line.strip())
    if key is not None:
        output[key] = _frontmatter_value(buffer)
    return output, description_line


def _frontmatter_value(parts: list[str]) -> str:
    value = " ".join(parts).strip().strip("'\"")
    if value in {">", ">-", "|", "|-"}:
        return ""
    if value.startswith((">- ", "|- ", "> ", "| ")):
        value = value.split(" ", 1)[1].strip()
    return value


def validate_skill_text(text: str, source: str = "SKILL.md") -> dict[str, str]:
    frontmatter, _ = parse_frontmatter(text)
    for field in ("name", "description"):
        if not frontmatter.get(field, "").strip():
            raise ScanError(f"{source} frontmatter must contain a non-empty {field}")
    try:
        paths.validate_skill_name(frontmatter["name"].strip())
    except paths.PathSafetyError as exc:
        raise ScanError(f"{source} has an invalid skill name: {exc}") from exc
    return frontmatter


def find_skill_md(root: Path) -> Path:
    try:
        matches = [
            child for child in root.iterdir()
            if child.name.lower() == "skill.md"
        ]
    except OSError as exc:
        raise ScanError(f"cannot read target directory: {exc}") from exc
    if len(matches) != 1:
        raise ScanError("skill directory must contain exactly one SKILL.md")
    skill_file = matches[0]
    if skill_file.is_symlink() or not skill_file.is_file():
        raise ScanError("SKILL.md must be a regular file, not a symlink")
    return skill_file


def validate_skill_directory(root: Path) -> tuple[Path, str, dict[str, str]]:
    try:
        if root.is_symlink() or _is_junction(root):
            raise ScanError("target root must not be a symlink or junction")
        if not root.is_dir():
            raise ScanError("target must be a directory")
        root.lstat()
    except OSError as exc:
        raise ScanError(f"cannot access target directory: {exc}") from exc
    skill_file = find_skill_md(root)
    try:
        text = skill_file.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ScanError(f"cannot read SKILL.md as UTF-8: {exc}") from exc
    frontmatter = validate_skill_text(text)
    return skill_file, text, frontmatter


def snippet_of(line: str, limit: int = 200) -> str:
    value = line.strip()
    return value if len(value) <= limit else value[:limit] + " ..."


def make_finding(
    rule: dict,
    file: str,
    line: int,
    snippet: str,
    context: list[str] | None = None,
) -> dict:
    is_semantic = rule["layer"] == "semantic"
    confidence = rule.get("confidence") or ("high" if not is_semantic else "medium")
    guidance = rule.get("guidance") or ""
    return models.Finding(
        rule_id=rule["id"],
        category=rule["category"],
        severity=rule["severity"],
        layer=rule["layer"],
        file=file,
        line=line,
        snippet=snippet,
        rationale=rule.get("rationale") or "",
        guidance=guidance,
        needs_semantic_review=is_semantic,
        confidence=confidence,
        context=context,
    ).as_dict()


def _context_window(lines: list[str], index: int) -> list[str]:
    low = max(0, index - CONTEXT_LINES)
    high = min(len(lines), index + CONTEXT_LINES + 1)
    return [f"{number + 1}: {lines[number]}" for number in range(low, high)]


def _is_junction(path: Path) -> bool:
    checker = getattr(path, "is_junction", None)
    if checker is not None:
        try:
            return bool(checker())
        except OSError:
            return True
    try:
        attributes = path.lstat().st_file_attributes  # type: ignore[attr-defined]
        import stat
        return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except AttributeError:
        return False
    except OSError:
        return True


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _boundary_finding(path: Path, relative: str, root: Path, rule_map: dict) -> dict:
    try:
        resolved = path.resolve(strict=True)
        internal = _is_within(resolved, root.resolve(strict=True))
        rule_id = "BOUNDARY-002" if internal else "BOUNDARY-001"
        detail = f"link resolves to {resolved}"
    except (OSError, RuntimeError) as exc:
        rule_id = "BOUNDARY-001"
        detail = f"broken or cyclic link: {exc}"
    return make_finding(_engine_rule(rule_map, rule_id), relative, 1, detail)


def discover_files(root: Path, rule_map: dict) -> tuple[list[Path], list[dict], list[dict]]:
    """Compatibility wrapper backed by the same snapshot policy as scanning."""

    try:
        snapshot = manifest_mod.build(root)
    except manifest_mod.ManifestError as exc:
        raise ScanError(str(exc)) from exc
    files = [root / Path(item.path) for item in snapshot.entries if item.scannable]
    findings = _manifest_boundary_findings(snapshot, rule_map)
    diagnostics = [item.as_dict() for item in snapshot.issues]
    return files, findings, diagnostics


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def scan_text(relative: str, text: str, rules: list[dict]) -> tuple[list[dict], dict[tuple[str, int], str]]:
    findings: list[dict] = []
    index: dict[tuple[str, int], str] = {}
    lines = text.splitlines()
    for line_number, line in enumerate(lines, start=1):
        index[(relative, line_number)] = line
        for rule in rules:
            if not rule.get("_regex") or rule.get("check"):
                continue
            if not rule_applies_to_file(rule, relative):
                continue
            if rule["_regex"].search(line):
                context = _context_window(lines, line_number - 1) if rule["layer"] == "semantic" else None
                findings.append(make_finding(rule, relative, line_number, snippet_of(line), context))
    for rule in rules:
        if not rule.get("check") or rule["check"] == "description-mismatch":
            continue
        if not rule_applies_to_file(rule, relative):
            continue
        for line_number, snippet in analyzers.run_named_check(rule, relative, text):
            findings.append(make_finding(rule, relative, line_number, snippet_of(snippet)))
    return findings, index


def scan_repo(
    root: Path,
    rules: list[dict],
    config: cfg.Config,
    content_manifest: manifest_mod.ContentManifest | None = None,
) -> tuple[list[str], list[dict], list[dict], dict[tuple[str, int], str]]:
    rule_map = {rule["id"]: rule for rule in rules}
    try:
        snapshot = content_manifest or manifest_mod.build(
            root,
            ignored_path=config.is_ignored_path,
            trusted_assets=config.trusted_assets,
        )
    except manifest_mod.ManifestError as exc:
        raise ScanError(str(exc)) from exc
    findings = _manifest_boundary_findings(snapshot, rule_map)
    diagnostics = [item.as_dict() for item in snapshot.issues]
    scanned: list[str] = []
    line_index: dict[tuple[str, int], str] = {}
    for entry in snapshot.entries:
        relative = entry.path
        if entry.disposition in {
            manifest_mod.ARCHIVE,
            manifest_mod.ARCHIVE_EXCLUDED,
        }:
            archive_findings, texts, archive_diagnostics = _scan_archive(
                entry.content or b"", relative, rules, rule_map
            )
            findings.extend(archive_findings)
            diagnostics.extend(archive_diagnostics)
            for member, text in texts:
                virtual = f"{relative}!{member}"
                member_findings, member_index = scan_text(virtual, text, rules)
                findings.extend(member_findings)
                line_index.update(member_index)
                scanned.append(virtual)
            scanned.append(relative)
            continue
        if entry.disposition not in {
            manifest_mod.SCAN,
            manifest_mod.SCAN_EXCLUDED,
        } or entry.content is None:
            continue
        text = entry.content.decode("utf-8")
        file_findings, file_index = scan_text(relative, text, rules)
        findings.extend(file_findings)
        line_index.update(file_index)
        scanned.append(relative)
    return scanned, findings, diagnostics, line_index


def _engine_rule(rule_map: dict, rule_id: str) -> dict:
    # Filesystem and archive integrity are engine invariants.  A custom catalog
    # must never lower their severity or replace their rationale/effect.
    candidate = rule_map.get(rule_id)
    rule = (
        candidate
        if candidate is not None and candidate.get("_engine_builtin") is True
        else _ENGINE_RULES.get(rule_id)
    )
    if rule is None:
        raise ScanError(f"required engine rule is unavailable: {rule_id}")
    return rule


def _manifest_boundary_findings(
    snapshot: manifest_mod.ContentManifest,
    rule_map: dict,
) -> list[dict]:
    findings = []
    for entry in snapshot.entries:
        if entry.disposition != manifest_mod.BOUNDARY:
            continue
        rule_id, _, remainder = (entry.detail or "BOUNDARY-001\0filesystem link").partition("\0")
        detail, _, _target = remainder.partition("\0")
        findings.append(make_finding(
            _engine_rule(rule_map, rule_id), entry.path, 1, detail or "filesystem link"
        ))
    return findings


def _scan_archive(content: bytes, display: str, rules: list[dict], rule_map: dict):
    try:
        raw_findings, texts, diagnostics = archives.inspect_archive(content)
    except archives.ArchiveError as exc:
        diagnostics = [{
            "path": manifest_mod.safe_display(display),
            "message": manifest_mod.safe_display(str(exc)),
            "blocking": True,
            "code": "uninspectable-archive",
        }]
        return [], [], diagnostics
    findings = [
        make_finding(
            _engine_rule(rule_map, item["rule_id"]),
            f"{display}!{item['member']}",
            1,
            item["message"],
        )
        for item in raw_findings
    ]
    diagnostics = [
        {
            **item,
            "path": f"{display}!{item.get('path', '')}".rstrip("!"),
            "blocking": True,
        }
        for item in diagnostics
    ]
    return findings, texts, diagnostics


def _scan_direct_archive(
    path: Path,
    rules: list[dict],
    content_manifest: manifest_mod.ContentManifest,
):
    rule_map = {rule["id"]: rule for rule in rules}
    diagnostics: list[dict] = []
    archive_entry = next(
        (item for item in content_manifest.entries if item.disposition == manifest_mod.ARCHIVE),
        None,
    )
    if archive_entry is None or archive_entry.content is None:
        diagnostics.append({
            "path": manifest_mod.safe_display(path.name),
            "message": "archive could not be captured for inspection",
            "blocking": True,
            "code": "uninspectable-archive",
        })
        return [], [], diagnostics, {}, path.name, "", {}, []
    archive_findings, texts, archive_diagnostics = _scan_archive(
        archive_entry.content, path.name, rules, rule_map
    )
    diagnostics.extend(archive_diagnostics)
    prefix: str | None
    try:
        prefix = archives.validate_archive_skill(texts)
    except archives.ArchiveError as exc:
        prefix = None
        diagnostics.append({
            "path": manifest_mod.safe_display(path.name),
            "message": manifest_mod.safe_display(str(exc)),
            "blocking": True,
            "code": "invalid-archive-skill",
        })
    skill_matches = [
        (name, text)
        for name, text in texts
        if (
            PurePosixPath(name).name.lower() == "skill.md"
            if prefix is None
            else name.lower() == (prefix + "skill.md").lower()
        )
    ]
    skill_location = path.name
    skill_text = ""
    frontmatter: dict[str, str] = {}
    if len(skill_matches) == 1:
        member_name, skill_text = skill_matches[0]
        skill_location = f"{path.name}!{member_name}"
        try:
            frontmatter = validate_skill_text(skill_text, member_name)
        except ScanError as exc:
            diagnostics.append({
                "path": manifest_mod.safe_display(skill_location),
                "message": manifest_mod.safe_display(str(exc)),
                "blocking": True,
                "code": "invalid-archive-skill",
            })
    elif not any(item.get("code") == "invalid-archive-skill" for item in diagnostics):
        diagnostics.append({
            "path": manifest_mod.safe_display(path.name),
            "message": "archive must contain exactly one readable SKILL.md",
            "blocking": True,
            "code": "invalid-archive-skill",
        })
    findings = list(archive_findings)
    scanned: list[str] = []
    line_index: dict[tuple[str, int], str] = {}
    ignored_configs = [
        name for name, _ in texts
        if (prefix is None or name.startswith(prefix))
        and PurePosixPath(name).name.lower() in {
            config_name.lower() for config_name in cfg.CONFIG_FILENAMES
        }
    ]
    for member, text in texts:
        if prefix is not None and prefix and not member.startswith(prefix):
            continue
        if member in ignored_configs:
            continue
        virtual = f"{path.name}!{member}"
        member_findings, member_index = scan_text(virtual, text, rules)
        findings.extend(member_findings)
        line_index.update(member_index)
        scanned.append(virtual)
    return (
        scanned,
        findings,
        diagnostics,
        line_index,
        skill_location,
        skill_text,
        frontmatter,
        ignored_configs,
    )


def check_description_mismatch(skill_text: str, skill_location: str,
                               findings: list[dict], rule: dict) -> list[dict]:
    frontmatter, description_line = parse_frontmatter(skill_text)
    description = frontmatter.get("description", "").lower()
    benign = description and not any(term in description for term in _MISMATCH_SENSITIVE_TERMS)
    serious = sorted({
        finding["category"] for finding in findings
        if finding["severity"] == CRITICAL
        and finding["category"] in _MISMATCH_TRIGGER_CATS
        and not finding.get("suppressed")
    })
    if not (benign and serious):
        return []
    finding = make_finding(
        rule,
        skill_location,
        description_line or 1,
        snippet_of("description: " + frontmatter.get("description", "")),
        [f"description: {frontmatter.get('description', '')}"],
    )
    finding["guidance"] = (
        finding["guidance"] + " Observed high-risk behavior: " + ", ".join(serious) + "."
    ).strip()
    finding["recommendation"] = finding["guidance"]
    return [finding]


def _apply_suppression(findings: list[dict], line_index: dict, config: cfg.Config) -> None:
    for finding in findings:
        line_text = line_index.get((finding["file"], finding["line"]), finding.get("snippet", ""))
        reason = config.suppression_reason(finding, line_text)
        if reason:
            finding["suppressed"] = True
            finding["suppressed_reason"] = reason


def _sort_key(finding: dict):
    return (
        -SEVERITY_RANK[finding["severity"]],
        finding["category"],
        finding["file"],
        finding["line"],
        finding["rule_id"],
    )


def normalize(findings: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    output = []
    for finding in sorted(findings, key=_sort_key):
        key = (finding["rule_id"], finding["file"], finding["line"], finding["snippet"])
        if key not in seen:
            seen.add(key)
            output.append(finding)
    return output
