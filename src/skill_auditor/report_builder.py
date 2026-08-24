"""Report construction, caching, recursive aggregation, and rendering."""

from __future__ import annotations

import os
from pathlib import Path

from . import __version__
from . import (
    baseline as baseline_mod,
    cache as cache_mod,
    config as cfg,
    formats,
    identity,
    manifest as manifest_mod,
    models,
    sanitize,
    semantic,
)
from .errors import ScanError
from .rules_loader import CRITICAL, INFO, SEVERITY_RANK, WARNING
from .scanner import (
    _apply_suppression,
    _is_junction,
    _is_within,
    _relative,
    _scan_direct_archive,
    check_description_mismatch,
    normalize,
    scan_repo,
    validate_skill_text,
)

VERSION = __version__
RECURSIVE_METADATA_DIRS = {
    ".git",
    ".pytest_cache",
    ".skill-auditor-cache",
    "__pycache__",
}
REPORT_SCHEMA = "skill-auditor-report/v1"
FINDING_DEPRECATIONS = [
    {"legacy": "rule_id", "replacement": "id", "remove_in": "1.0"},
    {"legacy": "rationale", "replacement": "explanation", "remove_in": "1.0"},
    {"legacy": "guidance", "replacement": "recommendation", "remove_in": "1.0"},
]

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
    content_manifest: manifest_mod.ContentManifest | None = None,
    source_info: dict | None = None,
    trusted_config: cfg.Config | None = None,
) -> dict:
    scan_options = models.ScanOptions(
        min_severity=min_severity,
        fail_on=fail_on,
        archive_target=archive_target,
        source_root=source_root,
    )
    if trusted_config is None:
        try:
            trusted_config = cfg.load_config(config_path, root)
        except cfg.ConfigError as exc:
            raise ScanError(str(exc)) from exc
    try:
        snapshot = content_manifest or manifest_mod.build(
            root,
            ignored_path=trusted_config.is_ignored_path,
            trusted_assets=trusted_config.trusted_assets,
            archive_target=scan_options.archive_target,
        )
    except manifest_mod.ManifestError as exc:
        raise ScanError(str(exc)) from exc
    ignored_target_config: list[str] = []
    if scan_options.archive_target:
        (
            scanned,
            findings,
            diagnostics,
            line_index,
            skill_location,
            skill_text,
            frontmatter,
            ignored_target_config,
        ) = _scan_direct_archive(root, rules, snapshot)
    else:
        skill_location, skill_text, frontmatter = _validate_skill_snapshot(snapshot)
        config_names = {name.lower() for name in cfg.CONFIG_FILENAMES}
        ignored_target_config = sorted(
            item.path
            for item in snapshot.entries
            if "/" not in item.path
            and item.path.lower() in config_names
        )
        scanned, findings, diagnostics, line_index = scan_repo(
            root, rules, trusted_config, snapshot
        )
    mismatch_rule = next(
        (rule for rule in rules if rule.get("check") == "description-mismatch"),
        None,
    )
    if mismatch_rule and skill_text and frontmatter:
        findings.extend(check_description_mismatch(
            skill_text, skill_location, findings, mismatch_rule
        ))
    _apply_suppression(findings, line_index, trusted_config)
    normalized = normalize(findings)
    active = [finding for finding in normalized if not finding["suppressed"]]
    suppressed = [finding for finding in normalized if finding["suppressed"]]
    source = _validate_source_root(root, scan_options.source_root)
    identity.enrich_findings(normalized, root, source)
    semantic_options = semantic.resolve_options(semantic_options or semantic.Options())
    semantic_policy = semantic.policy(semantic_options)
    scan_status = (
        "INCOMPLETE"
        if snapshot.scan_status == "INCOMPLETE"
        or any(item.get("blocking") for item in diagnostics)
        else "COMPLETE"
    )
    if semantic_options.mode == "off" or scan_status == "INCOMPLETE":
        for finding in active:
            finding["semantic_resolved"] = False
        semantic_reviews: list[dict] = []
    else:
        semantic_reviews = semantic.review_findings(
            active,
            description=frontmatter.get("description", ""),
            options=semantic_options,
        )
    catalog_digest = identity.rules_digest(rules)
    config_digest = _config_policy_digest(trusted_config)
    baseline_mod.validate_compatibility(
        baseline_data,
        tool_version=VERSION,
        rules_digest=catalog_digest,
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
    floor = SEVERITY_RANK[scan_options.min_severity]
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
    content_digest = snapshot.digest
    automation_id = _automation_id(root, source)
    skill_root = _source_relative(root, source)
    source_payload = dict(source_info or {"kind": "local", "path": str(root)})
    source_payload["content_hash"] = content_digest
    report_source_root = (
        "." if source_payload.get("kind") == "git"
        else str(source) if source else None
    )
    report = {
        "schema": REPORT_SCHEMA,
        "tool": "skill-auditor",
        "version": VERSION,
        "target": target,
        "scan_status": scan_status,
        "source": source_payload,
        "coverage": {
            **snapshot.coverage(),
            "scanned_files": len(set(scanned)),
            "archive_members_scanned": sum("!" in item for item in scanned),
        },
        "deprecations": FINDING_DEPRECATIONS,
        "skill_name": frontmatter.get("name"),
        "rules_loaded": len(rules),
        "fail_on": scan_options.fail_on,
        "min_severity": scan_options.min_severity,
        "config_source": trusted_config.source,
        "config_digest": config_digest,
        "source_root": report_source_root,
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
        "semantic": semantic_policy,
        "semantic_review": semantic_reviews,
        "baseline": _baseline_metadata(baseline_data, catalog_digest),
        "all_findings": active,
        "findings": displayed,
        "suppressed": suppressed,
        "full_verdict": full_verdict_code,
        "full_verdict_label": full_verdict_label,
        "verdict": verdict_code,
        "verdict_label": verdict_label,
        "exit_code": exit_code_for(gate_summary, scan_options.fail_on),
    }
    if scan_status == "INCOMPLETE":
        report["full_verdict"] = "ERROR"
        report["full_verdict_label"] = "INCOMPLETE SCAN"
        report["verdict"] = "ERROR"
        report["verdict_label"] = "INCOMPLETE SCAN"
        report["exit_code"] = 3
    return models.ScanReport.from_dict(_sanitize_report(report)).as_dict()


def _config_policy_digest(config: cfg.Config) -> str:
    return cache_mod.key({
        "allow_domains": sorted(config.allow_domains),
        "suppress": config.suppress,
        "ignore_paths": config.ignore_paths,
        "trusted_assets": config.trusted_assets,
    })


def _sanitize_report(value):
    """Sanitize all untrusted string values before caching or rendering."""

    if isinstance(value, str):
        return sanitize.safe_display(value)
    if isinstance(value, list):
        return [_sanitize_report(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_report(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize_report(item) for key, item in value.items()}
    return value


def _validate_skill_snapshot(
    snapshot: manifest_mod.ContentManifest,
) -> tuple[str, str, dict[str, str]]:
    matches = [
        item for item in snapshot.entries
        if "/" not in item.path and item.path.lower() == "skill.md"
    ]
    if len(matches) != 1:
        raise ScanError("skill directory must contain exactly one SKILL.md")
    skill = matches[0]
    if skill.disposition != manifest_mod.SCAN or skill.content is None:
        raise ScanError("SKILL.md must be inspectable UTF-8 text")
    text = skill.content.decode("utf-8")
    return skill.path, text, validate_skill_text(text, skill.path)


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
    visited_entries = 0

    def walk(directory: Path, depth: int = 0) -> None:
        nonlocal visited_entries
        if depth > manifest_mod.MAX_DEPTH:
            raise ScanError("recursive discovery exceeds the directory depth limit")
        try:
            remaining = max(manifest_mod.MAX_ENTRIES - visited_entries, 0)
            collected: list[os.DirEntry] = []
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    if len(collected) >= remaining:
                        raise ScanError("recursive discovery exceeds the entry limit")
                    collected.append(entry)
            entries = sorted(collected, key=lambda item: item.name.lower())
        except OSError as exc:
            raise ScanError(f"cannot read recursive scan directory: {exc}") from exc
        visited_entries += len(entries)
        skill_files = []
        for entry in entries:
            relative = _relative(Path(entry.path), root)
            if manifest_mod.unsafe_relative_path(relative):
                raise ScanError("recursive discovery encountered an unsafe path")
            try:
                if entry.is_symlink() or _is_junction(Path(entry.path)):
                    raise ScanError(
                        "recursive discovery encountered a filesystem link"
                    )
                if (
                    entry.name.lower() == "skill.md"
                    and entry.is_file(follow_symlinks=False)
                ):
                    skill_files.append(entry)
            except OSError as exc:
                raise ScanError(
                    f"cannot inspect recursive scan entry: {exc}"
                ) from exc
        if len(skill_files) > 1:
            raise ScanError(
                "recursive scan directory contains multiple case-insensitive SKILL.md files"
            )
        if len(skill_files) == 1:
            discovered.append(directory)
        for entry in entries:
            if entry.name.lower() in RECURSIVE_METADATA_DIRS:
                continue
            path = Path(entry.path)
            try:
                if entry.is_dir(follow_symlinks=False):
                    walk(path, depth + 1)
                elif not entry.is_file(follow_symlinks=False):
                    raise ScanError(
                        "recursive discovery encountered a non-regular filesystem entry"
                    )
            except OSError as exc:
                raise ScanError(
                    f"cannot inspect recursive scan entry: {exc}"
                ) from exc

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
    source_info: dict | None = None,
) -> dict:
    scan_options = models.ScanOptions(
        min_severity=min_severity,
        fail_on=fail_on,
        source_root=source_root,
    )
    source = _validate_source_root(root, scan_options.source_root)
    try:
        trusted_config = cfg.load_config(config_path, root)
    except cfg.ConfigError as exc:
        raise ScanError(str(exc)) from exc
    effective_semantic = semantic.resolve_options(semantic_options or semantic.Options())
    catalog_digest = identity.rules_digest(rules)
    baseline_mod.validate_compatibility(
        baseline_data,
        tool_version=VERSION,
        rules_digest=catalog_digest,
    )
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
            min_severity=scan_options.min_severity,
            fail_on=scan_options.fail_on,
            config_path=config_path,
            source_root=source,
            semantic_options=effective_semantic,
            cache_directory=resolved_cache,
            use_cache=use_cache,
            source_info={
                **(source_info or {"kind": "local", "path": str(root)}),
                "skill_root": str(skill_root.relative_to(root)).replace("\\", "/") or ".",
            },
            trusted_config=trusted_config,
        )
        for skill_root in skill_roots
    ]
    all_findings = [
        item for report in reports for item in report["all_findings"]
    ]
    if baseline_data is not None:
        baseline_mod.classify(all_findings, baseline_data)
        for child_report in reports:
            _refresh_gate(
                child_report,
                scan_options.fail_on,
                baseline_enabled=True,
            )
            child_report["baseline"] = _baseline_metadata(
                baseline_data, catalog_digest
            )
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
    scan_status = (
        "INCOMPLETE"
        if any(report.get("scan_status") == "INCOMPLETE" for report in reports)
        else "COMPLETE"
    )
    report = {
        "schema": REPORT_SCHEMA,
        "tool": "skill-auditor",
        "version": VERSION,
        "target": target,
        "scan_status": scan_status,
        "source": {
            **(source_info or {"kind": "local", "path": str(root)}),
            "content_hash": identity.aggregate_content_hash(reports),
        },
        "coverage": {
            "skills": len(reports),
            "complete": sum(item.get("scan_status") == "COMPLETE" for item in reports),
            "incomplete": sum(item.get("scan_status") == "INCOMPLETE" for item in reports),
        },
        "deprecations": FINDING_DEPRECATIONS,
        "recursive": True,
        "source_root": (
            "." if (source_info or {}).get("kind") == "git" else str(source)
        ),
        "rules_loaded": len(rules),
        "rules_digest": catalog_digest,
        "config_source": trusted_config.source,
        "config_digest": _config_policy_digest(trusted_config),
        "semantic": semantic.policy(effective_semantic),
        "content_hash": identity.aggregate_content_hash(reports),
        "fail_on": scan_options.fail_on,
        "min_severity": scan_options.min_severity,
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
        "exit_code": exit_code_for(gate_summary, scan_options.fail_on),
        "baseline": _baseline_metadata(baseline_data, catalog_digest),
    }
    if scan_status == "INCOMPLETE":
        report["full_verdict"] = "ERROR"
        report["full_verdict_label"] = "INCOMPLETE SCAN"
        report["verdict"] = "ERROR"
        report["verdict_label"] = "INCOMPLETE SCAN"
        report["exit_code"] = 3
    return models.ScanReport.from_dict(_sanitize_report(report)).as_dict()


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
    content_manifest: manifest_mod.ContentManifest | None = None,
    source_info: dict | None = None,
    trusted_config: cfg.Config | None = None,
) -> dict:
    scan_options = models.ScanOptions(
        min_severity=min_severity,
        fail_on=fail_on,
        archive_target=archive_target,
        source_root=source_root,
    )
    semantic_options = semantic.resolve_options(semantic_options or semantic.Options())
    if not use_cache:
        return build_report(
            target,
            root,
            rules,
            min_severity=scan_options.min_severity,
            fail_on=scan_options.fail_on,
            config_path=config_path,
            archive_target=scan_options.archive_target,
            source_root=scan_options.source_root,
            baseline_data=baseline_data,
            semantic_options=semantic_options,
            content_manifest=content_manifest,
            source_info=source_info,
            trusted_config=trusted_config,
        )
    if trusted_config is None:
        try:
            trusted = cfg.load_config(config_path, root)
        except cfg.ConfigError as exc:
            raise ScanError(str(exc)) from exc
    else:
        trusted = trusted_config
    try:
        snapshot = content_manifest or manifest_mod.build(
            root,
            ignored_path=trusted.is_ignored_path,
            trusted_assets=trusted.trusted_assets,
            archive_target=scan_options.archive_target,
        )
    except manifest_mod.ManifestError as exc:
        raise ScanError(str(exc)) from exc
    source = _validate_source_root(root, scan_options.source_root)
    directory = cache_mod.validate_directory(
        Path(cache_directory) if cache_directory else cache_mod.default_directory(),
        root,
    )
    config_digest = _config_policy_digest(trusted)
    catalog_digest = identity.rules_digest(rules)
    baseline_mod.validate_compatibility(
        baseline_data,
        tool_version=VERSION,
        rules_digest=catalog_digest,
    )
    cache_key = cache_mod.key({
        "schema": 2,
        "tool_version": VERSION,
        "target": source_info or {"kind": "local", "path": str(root.resolve(strict=True))},
        "content_manifest": snapshot.digest,
        "rules_digest": catalog_digest,
        "config_digest": config_digest,
        "source_root": _source_relative(root, source),
        **scan_options.cache_policy(),
        "semantic": semantic.policy(semantic_options),
    })
    report = cache_mod.load(directory, cache_key)
    cache_hit = report is not None
    if report is not None:
        expected_policy = _sanitize_report(semantic.policy(semantic_options))
        if (
            report.get("version") != VERSION
            or report.get("content_hash") != snapshot.digest
            or report.get("rules_digest") != catalog_digest
            or report.get("config_digest") != config_digest
            or report.get("semantic") != expected_policy
            or report.get("fail_on") != scan_options.fail_on
            or report.get("min_severity") != scan_options.min_severity
            or (report.get("baseline") or {}).get("enabled") is not False
        ):
            raise cache_mod.CacheError(
                "cached report policy metadata failed integrity validation"
            )
    if report is None:
        report = build_report(
            target,
            root,
            rules,
            min_severity=scan_options.min_severity,
            fail_on=scan_options.fail_on,
            config_path=config_path,
            archive_target=scan_options.archive_target,
            source_root=source,
            baseline_data=None,
            semantic_options=semantic_options,
            content_manifest=snapshot,
            source_info=source_info,
            trusted_config=trusted,
        )
        if report.get("scan_status") == "COMPLETE":
            cache_mod.store(directory, cache_key, report)
    report["cache"] = {
        "enabled": True,
        "hit": cache_hit,
        "key": cache_key,
        "directory": str(directory),
    }
    if baseline_data is not None:
        baseline_mod.classify(report["all_findings"], baseline_data)
        _refresh_gate(report, scan_options.fail_on, baseline_enabled=True)
        report["baseline"] = _baseline_metadata(
            baseline_data, report["rules_digest"]
        )
    return models.ScanReport.from_dict(_sanitize_report(report)).as_dict()


def _baseline_metadata(data: dict | None, catalog_digest: str) -> dict:
    baseline = data or {}
    baseline_source = baseline.get("baseline_path")
    if baseline_source is None and isinstance(baseline.get("source"), str):
        baseline_source = baseline.get("source")
    return {
        "enabled": data is not None,
        "source": baseline_source,
        "report_schema": baseline.get("report_schema"),
        "scan_status": baseline.get("scan_status"),
        "report_source": (
            baseline.get("source") if isinstance(baseline.get("source"), dict) else None
        ),
        "coverage": baseline.get("coverage"),
        "semantic": baseline.get("semantic"),
        "tool_version": baseline.get("tool_version"),
        "rules_digest": baseline.get("rules_digest"),
        "rules_match": data is None or baseline.get("rules_digest") == catalog_digest,
    }


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
    if report.get("scan_status") == "INCOMPLETE":
        report["full_verdict"] = "ERROR"
        report["full_verdict_label"] = "INCOMPLETE SCAN"
        report["verdict"] = "ERROR"
        report["verdict_label"] = "INCOMPLETE SCAN"
        report["exit_code"] = 3


def _categories(findings: list[dict]) -> dict[str, int]:
    output: dict[str, int] = {}
    for finding in findings:
        output[finding["category"]] = output.get(finding["category"], 0) + 1
    return output


def build_collection_report(
    target: str,
    reports: list[dict],
    errors: list[dict],
    rules: list[dict],
    *,
    fail_on: str,
    min_severity: str,
    baseline_data: dict | None,
    semantic_options: semantic.Options,
    source_kind: str,
    installed: bool = False,
) -> dict:
    """Build one schema-valid report for an already-scanned collection."""

    all_findings = [
        finding for report in reports for finding in report["all_findings"]
    ]
    displayed = [
        finding for report in reports for finding in report["findings"]
    ]
    suppressed = [
        finding for report in reports for finding in report["suppressed"]
    ]
    effective = [
        finding for finding in all_findings
        if not finding.get("semantic_resolved", False)
    ]
    gated = [
        finding for finding in effective
        if baseline_data is None or finding.get("new", True)
    ]
    summary = _summary(effective, suppressed)
    gate_summary = _summary(gated, suppressed)
    scan_status = (
        "INCOMPLETE"
        if errors
        or any(report.get("scan_status") == "INCOMPLETE" for report in reports)
        else "COMPLETE"
    )
    content_hash = identity.aggregate_content_hash(reports)
    config_digests = sorted({
        report.get("config_digest")
        for report in reports
        if report.get("config_digest")
    })
    catalog_digest = identity.rules_digest(rules)
    aggregate = {
        "schema": REPORT_SCHEMA,
        "tool": "skill-auditor",
        "version": VERSION,
        "target": target,
        "scan_status": scan_status,
        "source": {
            "kind": source_kind,
            "content_hash": content_hash,
        },
        "coverage": {
            "skills": len(reports),
            "errors": len(errors),
            "complete": sum(
                report.get("scan_status") == "COMPLETE" for report in reports
            ),
            "incomplete": sum(
                report.get("scan_status") == "INCOMPLETE" for report in reports
            ),
        },
        "deprecations": FINDING_DEPRECATIONS,
        "installed": installed,
        "scanned": len(reports),
        "reports": reports,
        "errors": errors,
        "rules_loaded": len(rules),
        "rules_digest": catalog_digest,
        "config_source": reports[0].get("config_source") if reports else None,
        "config_digest": (
            config_digests[0]
            if len(config_digests) == 1
            else cache_mod.key({"config_digests": config_digests})
        ),
        "semantic": semantic.policy(semantic_options),
        "content_hash": content_hash,
        "fail_on": fail_on,
        "min_severity": min_severity,
        "scanned_files": sorted({
            (
                str(Path(report.get("skill_root") or ".") / item).replace(
                    "\\", "/"
                )
                if report.get("skill_root") not in {None, "."}
                else item
            )
            for report in reports
            for item in report.get("scanned_files", [])
        }),
        "scan_diagnostics": [
            diagnostic
            for report in reports
            for diagnostic in report.get("scan_diagnostics", [])
        ] + [
            {
                "path": error["target"],
                "message": error["error"],
                "blocking": True,
                "code": "installed-skill-scan-error",
            }
            for error in errors
        ],
        "detected_summary": _summary(all_findings, suppressed),
        "summary": summary,
        "gate_summary": gate_summary,
        "display_summary": _summary(displayed, suppressed),
        "categories": _categories(effective),
        "all_findings": all_findings,
        "findings": displayed,
        "suppressed": suppressed,
        "full_verdict": verdict_for(summary)[0],
        "full_verdict_label": verdict_for(summary)[1],
        "verdict": verdict_for(gate_summary)[0],
        "verdict_label": verdict_for(gate_summary)[1],
        "exit_code": exit_code_for(gate_summary, fail_on),
        "baseline": _baseline_metadata(baseline_data, catalog_digest),
    }
    if scan_status == "INCOMPLETE":
        aggregate.update({
            "full_verdict": "ERROR",
            "full_verdict_label": "INCOMPLETE SCAN",
            "verdict": "ERROR",
            "verdict_label": "INCOMPLETE SCAN",
            "exit_code": 3,
        })
    return models.ScanReport.from_dict(_sanitize_report(aggregate)).as_dict()


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
