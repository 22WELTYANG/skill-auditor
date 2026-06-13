"""Command-line scanner and guarded installer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import __version__
from . import (
    analyzers,
    archives,
    baseline as baseline_mod,
    cache as cache_mod,
    config as cfg,
    formats,
    identity,
    integrity,
    paths,
    semantic,
)
from .rules_loader import (
    CRITICAL,
    INFO,
    SEVERITY_RANK,
    WARNING,
    RuleError,
    load_rules,
    rule_applies_to_file,
)

VERSION = __version__
TEXT_SUFFIXES = {
    ".md", ".markdown", ".txt", ".sh", ".bash", ".zsh", ".fish",
    ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php",
    ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".env",
    ".ps1", ".bat", ".cmd", ".mdc", "",
}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".idea"}
MAX_BYTES = 1_000_000
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


class ScanError(ValueError):
    pass


@dataclass
class ResolvedTarget:
    path: Path
    temporary: Path | None = None
    archive: bool = False


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
    semantic = rule["layer"] == "semantic"
    confidence = rule.get("confidence") or ("high" if not semantic else "medium")
    guidance = rule.get("guidance") or ""
    return {
        "rule_id": rule["id"],
        "layer": rule["layer"],
        "rationale": rule.get("rationale") or "",
        "guidance": guidance,
        "needs_semantic_review": semantic,
        "confidence": confidence,
        "suppressed": False,
        "suppressed_reason": None,
        "context": context if semantic else None,
        "id": rule["id"],
        "category": rule["category"],
        "severity": rule["severity"],
        "file": file,
        "line": line,
        "snippet": snippet,
        "explanation": rule.get("rationale") or "",
        "recommendation": guidance or "Review this finding before trusting the skill.",
    }


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
            return False
    try:
        attributes = path.lstat().st_file_attributes  # type: ignore[attr-defined]
        import stat
        return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except (AttributeError, OSError):
        return False


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
    return make_finding(rule_map[rule_id], relative, 1, detail)


def discover_files(root: Path, rule_map: dict) -> tuple[list[Path], list[dict], list[dict]]:
    files: list[Path] = []
    findings: list[dict] = []
    diagnostics: list[dict] = []

    def walk(directory: Path) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name.lower())
        except OSError as exc:
            relative = _relative(directory, root)
            diagnostics.append({"path": relative, "message": f"cannot read directory: {exc}"})
            return
        for entry in entries:
            path = Path(entry.path)
            relative = _relative(path, root)
            try:
                if entry.is_symlink() or _is_junction(path):
                    findings.append(_boundary_finding(path, relative, root, rule_map))
                    diagnostics.append({"path": relative, "message": "link skipped; never followed"})
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if entry.name not in SKIP_DIRS:
                        walk(path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    diagnostics.append({"path": relative, "message": "non-regular file skipped"})
                    continue
                try:
                    size = path.lstat().st_size
                except OSError as exc:
                    diagnostics.append({"path": relative, "message": f"cannot stat file: {exc}"})
                    continue
                if archives.is_archive(path):
                    files.append(path)
                    continue
                if path.suffix.lower() not in TEXT_SUFFIXES:
                    diagnostics.append({"path": relative, "message": "unsupported file type skipped"})
                    continue
                if size > MAX_BYTES:
                    diagnostics.append({"path": relative, "message": "file exceeds scan size limit"})
                    continue
                try:
                    with path.open("rb") as handle:
                        if b"\x00" in handle.read(4096):
                            diagnostics.append({"path": relative, "message": "binary file skipped"})
                            continue
                except OSError as exc:
                    diagnostics.append({"path": relative, "message": f"cannot read file: {exc}"})
                    continue
                files.append(path)
            except OSError as exc:
                diagnostics.append({"path": relative, "message": f"filesystem error: {exc}"})

    walk(root)
    return sorted(files), findings, diagnostics


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
) -> tuple[list[str], list[dict], list[dict], dict[tuple[str, int], str]]:
    rule_map = {rule["id"]: rule for rule in rules}
    files, findings, diagnostics = discover_files(root, rule_map)
    scanned: list[str] = []
    line_index: dict[tuple[str, int], str] = {}
    for path in files:
        relative = _relative(path, root)
        if config.is_ignored_path(relative):
            diagnostics.append({"path": relative, "message": "ignored by trusted config"})
            continue
        if archives.is_archive(path):
            archive_findings, texts, archive_diagnostics = _scan_archive(path, relative, rules, rule_map)
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
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            diagnostics.append({"path": relative, "message": f"cannot read UTF-8 text: {exc}"})
            continue
        file_findings, file_index = scan_text(relative, text, rules)
        findings.extend(file_findings)
        line_index.update(file_index)
        scanned.append(relative)
    return scanned, findings, diagnostics, line_index


def _scan_archive(path: Path, display: str, rules: list[dict], rule_map: dict):
    try:
        raw_findings, texts, diagnostics = archives.inspect_archive(path)
    except archives.ArchiveError as exc:
        diagnostics = [{"path": display, "message": str(exc)}]
        return [], [], diagnostics
    findings = [
        make_finding(
            rule_map[item["rule_id"]],
            f"{display}!{item['member']}",
            1,
            item["message"],
        )
        for item in raw_findings
        if item["rule_id"] in rule_map
    ]
    return findings, texts, diagnostics


def _scan_direct_archive(path: Path, rules: list[dict], config: cfg.Config):
    rule_map = {rule["id"]: rule for rule in rules}
    archive_findings, texts, diagnostics = _scan_archive(path, path.name, rules, rule_map)
    try:
        prefix = archives.validate_archive_skill(texts)
    except archives.ArchiveError as exc:
        raise ScanError(str(exc)) from exc
    skill_matches = [(name, text) for name, text in texts
                     if name == prefix + "SKILL.md" or name.lower() == (prefix + "skill.md").lower()]
    if len(skill_matches) != 1:
        raise ScanError("archive must contain exactly one readable SKILL.md")
    validate_skill_text(skill_matches[0][1], skill_matches[0][0])
    findings = list(archive_findings)
    scanned = []
    line_index: dict[tuple[str, int], str] = {}
    for member, text in texts:
        if prefix and not member.startswith(prefix):
            continue
        virtual = f"{path.name}!{member}"
        member_findings, member_index = scan_text(virtual, text, rules)
        findings.extend(member_findings)
        line_index.update(member_index)
        scanned.append(virtual)
    ignored_configs = [
        name for name, _ in texts
        if name.startswith(prefix)
        and Path(name).name in cfg.CONFIG_FILENAMES
    ]
    return (
        scanned,
        findings,
        diagnostics,
        line_index,
        skill_matches[0][1],
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


def resolve_target(target: str) -> ResolvedTarget:
    if re.match(r"^(https?://|git@)", target) or target.startswith("github.com/"):
        url = target if not target.startswith("github.com/") else "https://" + target
        temporary = Path(tempfile.mkdtemp(prefix="skill-auditor-"))
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", url, str(temporary)],
                check=True,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            shutil.rmtree(temporary, ignore_errors=True)
            raise ScanError("git is not installed but a URL was given") from exc
        except subprocess.CalledProcessError as exc:
            shutil.rmtree(temporary, ignore_errors=True)
            message = (exc.stderr or "git clone failed").strip().replace("\n", " ")
            raise ScanError(message) from exc
        return ResolvedTarget(temporary, temporary, False)
    candidate = Path(target).expanduser()
    try:
        if not candidate.exists():
            raise ScanError(f"path does not exist: {target}")
        if candidate.is_symlink() or _is_junction(candidate):
            raise ScanError("target root must not be a symlink or junction")
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ScanError(f"cannot resolve target: {exc}") from exc
    if resolved.is_file() and archives.is_archive(resolved):
        return ResolvedTarget(resolved, None, True)
    if not resolved.is_dir():
        raise ScanError("target must be a skill directory or supported archive")
    return ResolvedTarget(resolved)


def _summary(findings: list[dict], suppressed: list[dict]) -> dict:
    return {
        CRITICAL: sum(item["severity"] == CRITICAL for item in findings),
        WARNING: sum(item["severity"] == WARNING for item in findings),
        INFO: sum(item["severity"] == INFO for item in findings),
        "total": len(findings),
        "needs_semantic_review": sum(item["needs_semantic_review"] for item in findings),
        "suppressed": len(suppressed),
    }


def verdict_for(summary: dict) -> tuple[str, str]:
    if summary[CRITICAL]:
        return "DO_NOT_INSTALL", "DO NOT INSTALL"
    if summary[WARNING]:
        return "REVIEW_BEFORE_INSTALL", "REVIEW BEFORE INSTALL"
    return "SAFE_TO_INSTALL", "SAFE TO INSTALL"


def exit_code_for(summary: dict, fail_on: str) -> int:
    floor = SEVERITY_RANK[fail_on]
    if not any(summary[severity] and SEVERITY_RANK[severity] >= floor
               for severity in (CRITICAL, WARNING, INFO)):
        return 0
    return 2 if summary[CRITICAL] else 1


def build_report(
    target: str,
    root: Path,
    rules: list[dict],
    *,
    min_severity: str,
    fail_on: str,
    config_path: str | Path | None = None,
    archive_target: bool = False,
    source_root: str | Path | None = None,
    baseline_data: dict | None = None,
    semantic_options: semantic.Options | None = None,
) -> dict:
    try:
        trusted_config = cfg.load_config(config_path, root)
    except cfg.ConfigError as exc:
        raise ScanError(str(exc)) from exc
    ignored_target_config: list[str] = []
    if archive_target:
        (
            scanned,
            findings,
            diagnostics,
            line_index,
            skill_text,
            ignored_target_config,
        ) = _scan_direct_archive(root, rules, trusted_config)
        skill_location = next(
            item for item in scanned if item.lower().endswith("skill.md")
        )
    else:
        skill_file, skill_text, frontmatter = validate_skill_directory(root)
        ignored_target_config = cfg.target_config_files(root)
        scanned, findings, diagnostics, line_index = scan_repo(root, rules, trusted_config)
        skill_location = _relative(skill_file, root)
    if archive_target:
        frontmatter, _ = parse_frontmatter(skill_text)
    mismatch_rule = next(
        (rule for rule in rules if rule.get("check") == "description-mismatch"),
        None,
    )
    if mismatch_rule:
        findings.extend(check_description_mismatch(
            skill_text, skill_location, findings, mismatch_rule
        ))
    _apply_suppression(findings, line_index, trusted_config)
    normalized = normalize(findings)
    active = [finding for finding in normalized if not finding["suppressed"]]
    suppressed = [finding for finding in normalized if finding["suppressed"]]
    source = _validate_source_root(root, source_root)
    identity.enrich_findings(normalized, root, source)
    semantic_options = semantic_options or semantic.Options()
    if semantic_options.mode == "off":
        for finding in active:
            finding["semantic_resolved"] = False
        semantic_reviews: list[dict] = []
    else:
        semantic_reviews = semantic.review_findings(
            active,
            description=frontmatter.get("description", ""),
            options=semantic_options,
        )
    baseline_mod.classify(active, baseline_data)
    effective = [
        finding for finding in active
        if not finding.get("semantic_resolved", False)
    ]
    gated = [
        finding for finding in effective
        if baseline_data is None or finding.get("new", True)
    ]
    detected_summary = _summary(active, suppressed)
    summary = _summary(effective, suppressed)
    gate_summary = _summary(gated, suppressed)
    floor = SEVERITY_RANK[min_severity]
    displayed = [
        finding for finding in active
        if SEVERITY_RANK[finding["severity"]] >= floor
    ]
    display_summary = _summary(displayed, suppressed)
    categories: dict[str, int] = {}
    for finding in active:
        categories[finding["category"]] = categories.get(finding["category"], 0) + 1
    full_verdict_code, full_verdict_label = verdict_for(summary)
    verdict_code, verdict_label = verdict_for(gate_summary)
    content_digest = identity.content_hash(root)
    catalog_digest = identity.rules_digest(rules)
    automation_id = _automation_id(root, source)
    skill_root = _source_relative(root, source)
    return {
        "tool": "skill-auditor",
        "version": VERSION,
        "target": target,
        "rules_loaded": len(rules),
        "fail_on": fail_on,
        "min_severity": min_severity,
        "config_source": trusted_config.source,
        "source_root": str(source) if source else None,
        "skill_root": skill_root,
        "automation_id": automation_id,
        "content_hash": content_digest,
        "rules_digest": catalog_digest,
        "ignored_target_config": ignored_target_config,
        "scanned_files": sorted(set(scanned)),
        "scan_diagnostics": diagnostics,
        "detected_summary": detected_summary,
        "summary": summary,
        "gate_summary": gate_summary,
        "display_summary": display_summary,
        "categories": categories,
        "semantic": {
            "mode": semantic_options.mode,
            "model": semantic_options.model or None,
            "prompt_version": semantic.PROMPT_VERSION,
            "min_confidence": semantic_options.min_confidence,
        },
        "semantic_review": semantic_reviews,
        "baseline": {
            "enabled": baseline_data is not None,
            "source": (baseline_data or {}).get("source"),
            "rules_digest": (baseline_data or {}).get("rules_digest"),
            "rules_match": (
                baseline_data is None
                or baseline_data.get("rules_digest") == catalog_digest
            ),
        },
        "all_findings": active,
        "findings": displayed,
        "suppressed": suppressed,
        "full_verdict": full_verdict_code,
        "full_verdict_label": full_verdict_label,
        "verdict": verdict_code,
        "verdict_label": verdict_label,
        "exit_code": exit_code_for(gate_summary, fail_on),
    }


def _validate_source_root(root: Path, source_root: str | Path | None) -> Path | None:
    if source_root is None:
        return root.parent.resolve(strict=True) if root.is_file() else root.resolve(strict=True)
    candidate = Path(source_root).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
        physical = root.resolve(strict=True)
    except OSError as exc:
        raise ScanError(f"cannot resolve source root: {exc}") from exc
    if not resolved.is_dir() or not _is_within(physical, resolved):
        raise ScanError("source root must be a directory containing the scan target")
    return resolved


def _automation_id(root: Path, source_root: Path | None) -> str:
    return f"skill-auditor/{_source_relative(root, source_root)}"


def _source_relative(root: Path, source_root: Path | None) -> str:
    try:
        relative = root.resolve(strict=True).relative_to(source_root or root)
        value = str(relative).replace("\\", "/") or "."
    except (OSError, ValueError):
        value = root.name
    return value


def discover_skill_roots(root: Path) -> list[Path]:
    discovered: list[Path] = []

    def walk(directory: Path) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name.lower())
        except OSError as exc:
            raise ScanError(f"cannot read recursive scan directory: {exc}") from exc
        skill_files = [
            entry for entry in entries
            if entry.name.lower() == "skill.md"
            and entry.is_file(follow_symlinks=False)
            and not entry.is_symlink()
        ]
        if len(skill_files) == 1:
            discovered.append(directory)
        for entry in entries:
            if entry.name in SKIP_DIRS or entry.name == ".skill-auditor-cache":
                continue
            path = Path(entry.path)
            if entry.is_symlink() or _is_junction(path):
                continue
            if entry.is_dir(follow_symlinks=False):
                walk(path)

    walk(root)
    return discovered


def build_recursive_report(
    target: str,
    root: Path,
    rules: list[dict],
    *,
    min_severity: str,
    fail_on: str,
    config_path: str | Path | None = None,
    source_root: str | Path | None = None,
    baseline_data: dict | None = None,
    semantic_options: semantic.Options | None = None,
    cache_directory: str | Path | None = None,
    use_cache: bool = False,
) -> dict:
    source = _validate_source_root(root, source_root)
    if config_path is not None:
        try:
            cfg.load_config(config_path, root)
        except cfg.ConfigError as exc:
            raise ScanError(str(exc)) from exc
    resolved_cache = cache_directory
    if use_cache:
        resolved_cache = cache_mod.validate_directory(
            Path(cache_directory) if cache_directory else cache_mod.default_directory(),
            root,
        )
    skill_roots = discover_skill_roots(root)
    if not skill_roots:
        raise ScanError("recursive scan found no valid SKILL.md roots")
    reports = [
        build_report_cached(
            str(skill_root.relative_to(root)).replace("\\", "/") or ".",
            skill_root,
            rules,
            min_severity=min_severity,
            fail_on=fail_on,
            config_path=config_path,
            source_root=source,
            semantic_options=semantic_options,
            cache_directory=resolved_cache,
            use_cache=use_cache,
        )
        for skill_root in skill_roots
    ]
    all_findings = [
        item for report in reports for item in report["all_findings"]
    ]
    if baseline_data is not None:
        baseline_mod.classify(all_findings, baseline_data)
        for report in reports:
            _refresh_gate(report, fail_on, baseline_enabled=True)
    all_findings = [
        item for report in reports for item in report["all_findings"]
    ]
    displayed = [item for report in reports for item in report["findings"]]
    suppressed = [item for report in reports for item in report["suppressed"]]
    effective = [item for item in all_findings if not item.get("semantic_resolved")]
    gated = [
        item for item in effective
        if baseline_data is None or item.get("new", True)
    ]
    summary = _summary(effective, suppressed)
    gate_summary = _summary(gated, suppressed)
    detected_summary = _summary(all_findings, suppressed)
    verdict_code, verdict_label = verdict_for(gate_summary)
    full_code, full_label = verdict_for(summary)
    return {
        "tool": "skill-auditor",
        "version": VERSION,
        "target": target,
        "recursive": True,
        "source_root": str(source),
        "rules_loaded": len(rules),
        "rules_digest": identity.rules_digest(rules),
        "content_hash": identity.aggregate_content_hash(reports),
        "fail_on": fail_on,
        "min_severity": min_severity,
        "reports": reports,
        "scanned_files": sorted({
            (
                str(Path(report["skill_root"]) / item).replace("\\", "/")
                if report["skill_root"] != "."
                else item
            )
            for report in reports
            for item in report["scanned_files"]
        }),
        "scan_diagnostics": [
            item for report in reports for item in report["scan_diagnostics"]
        ],
        "detected_summary": detected_summary,
        "summary": summary,
        "gate_summary": gate_summary,
        "display_summary": _summary(displayed, suppressed),
        "categories": _categories(effective),
        "all_findings": all_findings,
        "findings": displayed,
        "suppressed": suppressed,
        "full_verdict": full_code,
        "full_verdict_label": full_label,
        "verdict": verdict_code,
        "verdict_label": verdict_label,
        "exit_code": exit_code_for(gate_summary, fail_on),
        "baseline": {
            "enabled": baseline_data is not None,
            "source": (baseline_data or {}).get("source"),
            "rules_digest": (baseline_data or {}).get("rules_digest"),
            "rules_match": (
                baseline_data is None
                or baseline_data.get("rules_digest") == identity.rules_digest(rules)
            ),
        },
    }


def build_report_cached(
    target: str,
    root: Path,
    rules: list[dict],
    *,
    min_severity: str,
    fail_on: str,
    config_path: str | Path | None = None,
    archive_target: bool = False,
    source_root: str | Path | None = None,
    baseline_data: dict | None = None,
    semantic_options: semantic.Options | None = None,
    cache_directory: str | Path | None = None,
    use_cache: bool = True,
) -> dict:
    semantic_options = semantic_options or semantic.Options()
    if not use_cache:
        return build_report(
            target,
            root,
            rules,
            min_severity=min_severity,
            fail_on=fail_on,
            config_path=config_path,
            archive_target=archive_target,
            source_root=source_root,
            baseline_data=baseline_data,
            semantic_options=semantic_options,
        )
    try:
        trusted = cfg.load_config(config_path, root)
    except cfg.ConfigError as exc:
        raise ScanError(str(exc)) from exc
    source = _validate_source_root(root, source_root)
    directory = cache_mod.validate_directory(
        Path(cache_directory) if cache_directory else cache_mod.default_directory(),
        root,
    )
    config_digest = ""
    if trusted.source:
        try:
            config_digest = hashlib.sha256(
                Path(trusted.source).read_bytes()
            ).hexdigest()
        except OSError as exc:
            raise ScanError(f"cannot hash trusted config: {exc}") from exc
    cache_key = cache_mod.key({
        "schema": 1,
        "tool_version": VERSION,
        "target": str(root.resolve(strict=True)),
        "content_hash": identity.content_hash(root),
        "rules_digest": identity.rules_digest(rules),
        "config_digest": config_digest,
        "source_root": str(source),
        "archive_target": archive_target,
        "min_severity": min_severity,
        "fail_on": fail_on,
        "semantic": {
            "mode": semantic_options.mode,
            "model": semantic_options.model,
            "base_url": semantic_options.base_url,
            "timeout": semantic_options.timeout,
            "min_confidence": semantic_options.min_confidence,
            "prompt_version": semantic.PROMPT_VERSION,
        },
    })
    report = cache_mod.load(directory, cache_key)
    cache_hit = report is not None
    if report is None:
        report = build_report(
            target,
            root,
            rules,
            min_severity=min_severity,
            fail_on=fail_on,
            config_path=config_path,
            archive_target=archive_target,
            source_root=source,
            baseline_data=None,
            semantic_options=semantic_options,
        )
        cache_mod.store(directory, cache_key, report)
    report["cache"] = {
        "enabled": True,
        "hit": cache_hit,
        "key": cache_key,
        "directory": str(directory),
    }
    if baseline_data is not None:
        baseline_mod.classify(report["all_findings"], baseline_data)
        _refresh_gate(report, fail_on, baseline_enabled=True)
        report["baseline"] = {
            "enabled": True,
            "source": baseline_data.get("source"),
            "rules_digest": baseline_data.get("rules_digest"),
            "rules_match": baseline_data.get("rules_digest") == report["rules_digest"],
        }
    return report


def _refresh_gate(report: dict, fail_on: str, *, baseline_enabled: bool) -> None:
    effective = [
        item for item in report.get("all_findings", report["findings"])
        if not item.get("semantic_resolved")
    ]
    gated = [
        item for item in effective
        if not baseline_enabled or item.get("new", True)
    ]
    report["summary"] = _summary(effective, report["suppressed"])
    report["gate_summary"] = _summary(gated, report["suppressed"])
    report["full_verdict"], report["full_verdict_label"] = verdict_for(
        report["summary"]
    )
    report["verdict"], report["verdict_label"] = verdict_for(
        report["gate_summary"]
    )
    report["exit_code"] = exit_code_for(report["gate_summary"], fail_on)


def _categories(findings: list[dict]) -> dict[str, int]:
    output: dict[str, int] = {}
    for finding in findings:
        output[finding["category"]] = output.get(finding["category"], 0) + 1
    return output


def render_report(report: dict, output_format: str, rules: list[dict], *, verbose: bool) -> str:
    if output_format in {"pretty", "text"}:
        return formats.render_pretty(report, verbose=verbose)
    if output_format == "json":
        return formats.render_json(report)
    if output_format == "markdown":
        return formats.render_markdown(report)
    if output_format == "sarif":
        return formats.render_sarif(report, rules)
    raise ScanError(f"unknown format: {output_format}")


def _build_for_resolved(args, rules: list[dict], resolved: ResolvedTarget) -> dict:
    return build_report_cached(
        args.target,
        resolved.path,
        rules,
        min_severity=args.min_severity,
        fail_on=args.fail_on,
        config_path=args.config,
        archive_target=resolved.archive,
        source_root=args.source_root,
        baseline_data=getattr(args, "_baseline_data", None),
        semantic_options=_semantic_options(args),
        cache_directory=args.cache_dir,
        use_cache=not args.no_cache,
    )


def cmd_scan(args, rules: list[dict]) -> int:
    if args.all:
        return _scan_all(args, rules)
    resolved: ResolvedTarget | None = None
    try:
        args._baseline_data = (
            baseline_mod.load(args.baseline) if args.baseline else None
        )
        resolved = resolve_target(args.target)
        if args.recursive:
            if resolved.archive:
                raise ScanError("--recursive requires a directory target")
            report = build_recursive_report(
                args.target,
                resolved.path,
                rules,
                min_severity=args.min_severity,
                fail_on=args.fail_on,
                config_path=args.config,
                source_root=args.source_root,
                baseline_data=args._baseline_data,
                semantic_options=_semantic_options(args),
                cache_directory=args.cache_dir,
                use_cache=not args.no_cache,
            )
        else:
            report = _build_for_resolved(args, rules, resolved)
        rendered = render_report(report, args.format, rules, verbose=args.verbose)
        _emit_output(rendered, args.output)
        return report["exit_code"]
    except (
        ScanError,
        baseline_mod.BaselineError,
        cache_mod.CacheError,
        semantic.SemanticError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    finally:
        if resolved and resolved.temporary:
            shutil.rmtree(resolved.temporary, ignore_errors=True)


def _build_command_report(args, rules: list[dict], resolved: ResolvedTarget) -> dict:
    args._baseline_data = None
    if args.recursive:
        if resolved.archive:
            raise ScanError("--recursive requires a directory target")
        return build_recursive_report(
            args.target,
            resolved.path,
            rules,
            min_severity=args.min_severity,
            fail_on=args.fail_on,
            config_path=args.config,
            source_root=args.source_root,
            semantic_options=_semantic_options(args),
            cache_directory=args.cache_dir,
            use_cache=not args.no_cache,
        )
    return _build_for_resolved(args, rules, resolved)


def cmd_baseline(args, rules: list[dict]) -> int:
    if not args.output:
        print("error: baseline create requires --output", file=sys.stderr)
        return 3
    resolved: ResolvedTarget | None = None
    try:
        resolved = resolve_target(args.target)
        report = _build_command_report(args, rules, resolved)
        integrity.write(args.output, baseline_mod.build(report))
        print(f"wrote baseline: {Path(args.output).expanduser()}")
        return 0
    except (
        ScanError,
        baseline_mod.BaselineError,
        cache_mod.CacheError,
        integrity.LockError,
        semantic.SemanticError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    finally:
        if resolved and resolved.temporary:
            shutil.rmtree(resolved.temporary, ignore_errors=True)


def cmd_lock(args, rules: list[dict]) -> int:
    resolved: ResolvedTarget | None = None
    try:
        resolved = resolve_target(args.target)
        report = _build_command_report(args, rules, resolved)
        if args.lock_command == "create":
            if not args.output:
                raise ScanError("lock create requires --output")
            integrity.write(args.output, integrity.build(report))
            print(f"wrote lockfile: {Path(args.output).expanduser()}")
            return report["exit_code"]
        lock = integrity.load(args.lock)
        changed = integrity.differences(report, lock)
        if changed:
            print("lock verification failed: " + ", ".join(changed), file=sys.stderr)
            return 1
        print("lock verification passed")
        return 0
    except (
        ScanError,
        cache_mod.CacheError,
        integrity.LockError,
        semantic.SemanticError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    finally:
        if resolved and resolved.temporary:
            shutil.rmtree(resolved.temporary, ignore_errors=True)


def _scan_all(args, rules: list[dict]) -> int:
    skills = paths.installed_skills()
    reports = []
    errors = []
    for skill in skills:
        try:
            reports.append(build_report(
                str(skill),
                skill.resolve(strict=True),
                rules,
                min_severity=args.min_severity,
                fail_on=args.fail_on,
                config_path=args.config,
            ))
        except (ScanError, OSError) as exc:
            errors.append({"target": str(skill), "error": str(exc), "exit_code": 3})
    if args.format == "json":
        rendered = json.dumps({
            "tool": "skill-auditor",
            "version": VERSION,
            "scanned": len(reports),
            "reports": reports,
            "errors": errors,
        }, indent=2, ensure_ascii=False)
    elif args.format == "sarif":
        merged = {
            "version": VERSION,
            "findings": [finding for report in reports for finding in report["findings"]],
            "reports": reports,
        }
        rendered = formats.render_sarif(merged, rules)
    else:
        rendered = _summary_table(reports, errors)
    _emit_output(rendered, args.output)
    if errors:
        return 3
    return max((report["exit_code"] for report in reports), default=0)


def _summary_table(reports: list[dict], errors: list[dict]) -> str:
    output = [
        "=" * 64,
        f" skill-auditor v{VERSION} — audit of {len(reports)} installed skill(s)",
        "=" * 64,
    ]
    for report in reports:
        summary = report["summary"]
        output.append(
            f" {Path(report['target']).name}: {summary[CRITICAL]} critical, "
            f"{summary[WARNING]} warning — {report['verdict_label']}"
        )
    for error in errors:
        output.append(f" {Path(error['target']).name}: ERROR — {error['error']}")
    output.append("=" * 64)
    return "\n".join(output)


def _skill_name(root: Path) -> str:
    _, text, frontmatter = validate_skill_directory(root)
    return paths.validate_skill_name(frontmatter["name"].strip())


def _copy_ignore(_directory: str, names: list[str]) -> set[str]:
    ignored = {".git", "__pycache__", ".pytest_cache"}
    return {name for name in names if name in ignored or name.endswith((".pyc", ".pyo"))}


def _tree_contains_link(root: Path) -> bool:
    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in [*dirnames, *filenames]:
            candidate = base / name
            if candidate.is_symlink() or _is_junction(candidate):
                return True
    return False


def _do_install(root: Path, destination_name: str) -> list[Path]:
    installed = []
    for parent in paths.install_targets():
        try:
            parent_resolved, destination = paths.safe_install_destination(parent, destination_name)
            parent_resolved.mkdir(parents=True, exist_ok=True)
            if destination.is_symlink() or _is_junction(destination):
                raise ScanError(f"refusing to replace linked destination: {destination}")
            staging = Path(tempfile.mkdtemp(
                prefix=f".{destination_name}.staging-",
                dir=parent_resolved,
            ))
            shutil.rmtree(staging)
            backup = parent_resolved / f".{destination_name}.backup-{uuid.uuid4().hex}"
            try:
                shutil.copytree(root, staging, symlinks=True, ignore=_copy_ignore)
                if _tree_contains_link(staging):
                    raise ScanError("staged installation contains a link")
                if destination.exists():
                    os.replace(destination, backup)
                os.replace(staging, destination)
                if backup.exists():
                    shutil.rmtree(backup)
            except Exception:
                if staging.exists():
                    shutil.rmtree(staging, ignore_errors=True)
                if backup.exists() and not destination.exists():
                    os.replace(backup, destination)
                raise
            installed.append(destination)
        except (OSError, paths.PathSafetyError) as exc:
            raise ScanError(f"install failed: {exc}") from exc
    return installed


def cmd_install(args, rules: list[dict]) -> int:
    resolved: ResolvedTarget | None = None
    try:
        resolved = resolve_target(args.target)
        if resolved.archive:
            raise ScanError("archive targets can be scanned but not installed")
        report = _build_for_resolved(args, rules, resolved)
        print(render_report(report, args.format, rules, verbose=args.verbose))
        if args.dry_run:
            print("\n[dry-run] scan only; nothing installed.")
            return report["exit_code"]
        boundary_count = report["categories"].get("filesystem-boundary", 0)
        if boundary_count:
            raise ScanError("refusing to install a skill containing filesystem links")
        summary = report["summary"]
        if not args.force and summary[CRITICAL]:
            print(f"\nRefusing to install: {summary[CRITICAL]} CRITICAL finding(s).", file=sys.stderr)
            return 2
        if not args.force and summary[WARNING]:
            if not _confirm(f"\n{summary[WARNING]} WARNING finding(s). Install anyway?"):
                print("Aborted.", file=sys.stderr)
                return 1
        destination_name = _skill_name(resolved.path)
        installed = _do_install(resolved.path, destination_name)
        print(f"\nInstalled '{destination_name}' to:")
        for destination in installed:
            print(f"   {destination}")
        return 0
    except ScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    finally:
        if resolved and resolved.temporary:
            shutil.rmtree(resolved.temporary, ignore_errors=True)


def _confirm(prompt: str) -> bool:
    if not sys.stdin or not sys.stdin.isatty():
        print(prompt + " [y/N] (non-interactive -> N)")
        return False
    try:
        return input(prompt + " [y/N] ").strip().lower() in {"y", "yes"}
    except EOFError:
        return False


def _severity(value: str) -> str:
    normalized = value.upper()
    if normalized not in SEVERITY_RANK:
        raise argparse.ArgumentTypeError("expected info, warning, or critical")
    return normalized


def _confidence(value: str) -> float:
    try:
        result = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected a number between 0 and 1") from exc
    if not 0 <= result <= 1:
        raise argparse.ArgumentTypeError("expected a number between 0 and 1")
    return result


def _semantic_options(args) -> semantic.Options:
    return semantic.Options(
        mode=getattr(args, "semantic", "off"),
        model=getattr(args, "semantic_model", "") or "",
        base_url=getattr(args, "semantic_base_url", "") or "",
        timeout=getattr(args, "semantic_timeout", 20.0),
        min_confidence=getattr(args, "semantic_min_confidence", 0.90),
    )


def _emit_output(content: str, output: str | None) -> None:
    if not output:
        print(content)
        return
    destination = Path(output).expanduser()
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(
            f".{destination.name}.{uuid.uuid4().hex}.tmp"
        )
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            if not content.endswith("\n"):
                handle.write("\n")
        os.replace(temporary, destination)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except (OSError, UnboundLocalError):
            pass
        raise ScanError(f"cannot write output file: {exc}") from exc


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=["pretty", "json", "sarif", "markdown", "text"],
        default="pretty",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "warning", "info"],
        default="critical",
    )
    parser.add_argument(
        "--min-severity",
        type=_severity,
        default=INFO,
        help="display threshold only; verdict always uses all findings",
    )
    parser.add_argument("--rules-dir", default=None)
    parser.add_argument("--config", help="trusted suppression config outside the target")
    parser.add_argument("--output", help="atomically write the selected format to a file")
    parser.add_argument("--source-root", help="repository root used for artifact paths")
    parser.add_argument("--baseline", help="trusted baseline JSON used for diff-aware gating")
    parser.add_argument("--cache-dir", help="trusted cache directory outside the target")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument(
        "--semantic",
        choices=["off", "api", "local"],
        default="off",
    )
    parser.add_argument("--semantic-model")
    parser.add_argument("--semantic-base-url")
    parser.add_argument("--semantic-timeout", type=float, default=20.0)
    parser.add_argument(
        "--semantic-min-confidence",
        type=_confidence,
        default=0.90,
    )
    parser.add_argument("-v", "--verbose", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skill-auditor",
        description="Scan an Agent skill for security risks and gate installs.",
    )
    parser.add_argument("--version", action="version", version=f"skill-auditor {VERSION}")
    commands = parser.add_subparsers(dest="command")
    scan_parser = commands.add_parser("scan")
    scan_parser.add_argument("target", nargs="?")
    scan_parser.add_argument("--all", action="store_true")
    scan_parser.add_argument("--recursive", action="store_true")
    _add_common(scan_parser)
    install_parser = commands.add_parser("install")
    install_parser.add_argument("target")
    install_parser.add_argument("--force", action="store_true")
    install_parser.add_argument("--dry-run", action="store_true")
    _add_common(install_parser)
    baseline_parser = commands.add_parser("baseline")
    baseline_commands = baseline_parser.add_subparsers(dest="baseline_command")
    baseline_create = baseline_commands.add_parser("create")
    baseline_create.add_argument("target")
    baseline_create.add_argument("--recursive", action="store_true")
    _add_common(baseline_create)
    lock_parser = commands.add_parser("lock")
    lock_commands = lock_parser.add_subparsers(dest="lock_command")
    lock_create = lock_commands.add_parser("create")
    lock_create.add_argument("target")
    lock_create.add_argument("--recursive", action="store_true")
    _add_common(lock_create)
    lock_verify = lock_commands.add_parser("verify")
    lock_verify.add_argument("target")
    lock_verify.add_argument("--lock", required=True)
    lock_verify.add_argument("--recursive", action="store_true")
    _add_common(lock_verify)
    return parser


_FAIL_ON = {"critical": CRITICAL, "warning": WARNING, "info": INFO}


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] not in {
        "scan", "install", "baseline", "lock", "-h", "--help", "--version"
    }:
        raw = ["scan"] + raw
    parser = build_parser()
    args = parser.parse_args(raw)
    if not args.command:
        parser.print_help()
        return 0
    args.fail_on = _FAIL_ON[args.fail_on]
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    try:
        rules = load_rules(args.rules_dir) if args.rules_dir else load_rules()
    except RuleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    if args.command == "scan":
        if not args.all and not args.target:
            print("error: scan needs a target, or --all", file=sys.stderr)
            return 3
        return cmd_scan(args, rules)
    if args.command == "install":
        return cmd_install(args, rules)
    if args.command == "baseline":
        if args.baseline_command != "create":
            print("error: baseline requires the create subcommand", file=sys.stderr)
            return 3
        return cmd_baseline(args, rules)
    if args.command == "lock":
        if args.lock_command not in {"create", "verify"}:
            print("error: lock requires create or verify", file=sys.stderr)
            return 3
        return cmd_lock(args, rules)
    return 3
