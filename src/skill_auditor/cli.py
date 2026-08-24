"""Command-line scanner and guarded installer."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import uuid
from pathlib import Path

from . import __version__
from . import (
    archives,
    baseline as baseline_mod,
    cache as cache_mod,
    config as cfg,
    identity,
    installer,
    integrity,
    manifest as manifest_mod,
    paths,
    sanitize,
    semantic,
    target as target_mod,
)
from .rules_loader import (
    CRITICAL,
    INFO,
    SEVERITY_RANK,
    WARNING,
    RuleError,
    load_rules,
)
from .errors import ScanError
from .report_builder import (
    FINDING_DEPRECATIONS,
    REPORT_SCHEMA,
    _baseline_metadata,
    _categories,
    _config_policy_digest,
    _refresh_gate,
    _sanitize_report,
    _source_relative,
    _summary,
    _validate_source_root,
    build_collection_report,
    build_recursive_report,
    build_report,
    build_report_cached,
    discover_skill_roots,
    exit_code_for,
    render_report,
    verdict_for,
)
from .scanner import (
    _apply_suppression,
    _boundary_finding,
    _context_window,
    _engine_rule,
    _frontmatter_value,
    _is_junction,
    _is_within,
    _manifest_boundary_findings,
    _relative,
    _scan_archive,
    _scan_direct_archive,
    _sort_key,
    check_description_mismatch,
    discover_files,
    find_skill_md,
    make_finding,
    normalize,
    parse_frontmatter,
    scan_repo,
    scan_text,
    snippet_of,
    validate_skill_directory,
    validate_skill_text,
)

VERSION = __version__


class ControlledArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ScanError(message)


ResolvedTarget = target_mod.ResolvedTarget


def resolve_target(target: str, ref: str | None = None) -> ResolvedTarget:
    try:
        return target_mod.resolve(target, ref)
    except target_mod.TargetError as exc:
        raise ScanError(str(exc)) from exc


def _build_for_resolved(
    args,
    rules: list[dict],
    resolved: ResolvedTarget,
    *,
    content_manifest: manifest_mod.ContentManifest | None = None,
    trusted_config: cfg.Config | None = None,
) -> dict:
    return build_report_cached(
        resolved.display_target or args.target,
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
        source_info=resolved.source,
        content_manifest=content_manifest,
        trusted_config=trusted_config,
    )


def cmd_scan(args, rules: list[dict]) -> int:
    resolved: ResolvedTarget | None = None
    try:
        args._baseline_data = (
            baseline_mod.load(args.baseline) if args.baseline else None
        )
        if args.all:
            return _scan_all(args, rules)
        resolved = resolve_target(args.target, args.ref)
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
                source_info=resolved.source,
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
        _print_error(exc)
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
            resolved.display_target or args.target,
            resolved.path,
            rules,
            min_severity=args.min_severity,
            fail_on=args.fail_on,
            config_path=args.config,
            source_root=args.source_root,
            semantic_options=_semantic_options(args),
            cache_directory=args.cache_dir,
            use_cache=not args.no_cache,
            source_info=resolved.source,
        )
    return _build_for_resolved(args, rules, resolved)


def cmd_baseline(args, rules: list[dict]) -> int:
    if not args.output:
        _print_error("baseline create requires --output")
        return 3
    resolved: ResolvedTarget | None = None
    try:
        resolved = resolve_target(args.target, args.ref)
        report = _build_command_report(args, rules, resolved)
        if report.get("scan_status") != "COMPLETE":
            raise ScanError("refusing to create a baseline from an incomplete scan")
        integrity.write(args.output, baseline_mod.build(report))
        _operation_log(
            args,
            "wrote baseline: "
            + manifest_mod.safe_display(str(Path(args.output).expanduser()))
        )
        return 0
    except (
        ScanError,
        baseline_mod.BaselineError,
        cache_mod.CacheError,
        integrity.LockError,
        semantic.SemanticError,
    ) as exc:
        _print_error(exc)
        return 3
    finally:
        if resolved and resolved.temporary:
            shutil.rmtree(resolved.temporary, ignore_errors=True)


def cmd_lock(args, rules: list[dict]) -> int:
    resolved: ResolvedTarget | None = None
    try:
        resolved = resolve_target(args.target, args.ref)
        report = _build_command_report(args, rules, resolved)
        if report.get("scan_status") != "COMPLETE":
            raise ScanError("refusing to use a lock with an incomplete scan")
        if args.lock_command == "create":
            if not args.output:
                raise ScanError("lock create requires --output")
            integrity.write(args.output, integrity.build(report))
            _operation_log(
                args,
                "wrote lockfile: "
                + manifest_mod.safe_display(str(Path(args.output).expanduser()))
            )
            return report["exit_code"]
        lock = integrity.load(args.lock)
        changed = integrity.differences(report, lock)
        if changed:
            print(
                "lock verification failed: "
                + manifest_mod.safe_display(", ".join(changed)),
                file=sys.stderr,
            )
            return 1
        _operation_log(args, "lock verification passed")
        return 0
    except (
        ScanError,
        cache_mod.CacheError,
        integrity.LockError,
        semantic.SemanticError,
    ) as exc:
        _print_error(exc)
        return 3
    finally:
        if resolved and resolved.temporary:
            shutil.rmtree(resolved.temporary, ignore_errors=True)


def _scan_all(args, rules: list[dict]) -> int:
    skills = paths.installed_skills()
    reports: list[dict] = []
    errors: list[dict] = []
    effective_semantic = semantic.resolve_options(_semantic_options(args))
    catalog_digest = identity.rules_digest(rules)
    baseline_mod.validate_compatibility(
        args._baseline_data,
        tool_version=VERSION,
        rules_digest=catalog_digest,
    )
    for skill in skills:
        try:
            reports.append(build_report_cached(
                str(skill),
                skill.resolve(strict=True),
                rules,
                min_severity=args.min_severity,
                fail_on=args.fail_on,
                config_path=args.config,
                source_root=args.source_root or skill.parent,
                baseline_data=args._baseline_data,
                semantic_options=effective_semantic,
                cache_directory=args.cache_dir,
                use_cache=not args.no_cache,
                source_info={"kind": "local", "path": str(skill)},
            ))
        except (
            ScanError,
            baseline_mod.BaselineError,
            cache_mod.CacheError,
            cfg.ConfigError,
            manifest_mod.ManifestError,
            semantic.SemanticError,
            OSError,
            UnicodeError,
            RecursionError,
        ) as exc:
            errors.append({
                "target": manifest_mod.safe_display(str(skill)),
                "error": _safe_error_message(exc),
                "exit_code": 3,
            })
    aggregate = build_collection_report(
        "--all",
        reports,
        errors,
        rules,
        fail_on=args.fail_on,
        min_severity=args.min_severity,
        baseline_data=args._baseline_data,
        semantic_options=effective_semantic,
        source_kind="installed-skills",
        installed=True,
    )
    if args.format in {"json", "sarif", "markdown"}:
        rendered = render_report(
            aggregate, args.format, rules, verbose=args.verbose
        )
    else:
        rendered = _summary_table(reports, errors)
    _emit_output(rendered, args.output)
    return aggregate["exit_code"]


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


def _do_install(
    root: Path,
    destination_name: str,
    content_manifest: manifest_mod.ContentManifest | None = None,
) -> list[Path]:
    try:
        snapshot = content_manifest or manifest_mod.build(root)
        return installer.install_snapshot(snapshot.install_entries(), destination_name)
    except (installer.InstallError, manifest_mod.ManifestError) as exc:
        raise ScanError(str(exc)) from exc


def cmd_install(args, rules: list[dict]) -> int:
    resolved: ResolvedTarget | None = None
    try:
        resolved = resolve_target(args.target, args.ref)
        if resolved.archive:
            raise ScanError("archive targets can be scanned but not installed")
        try:
            trusted = cfg.load_config(args.config, resolved.path)
            snapshot = manifest_mod.build(
                resolved.path,
                ignored_path=trusted.is_ignored_path,
                trusted_assets=trusted.trusted_assets,
            )
        except (cfg.ConfigError, manifest_mod.ManifestError) as exc:
            raise ScanError(str(exc)) from exc
        report = _build_for_resolved(
            args,
            rules,
            resolved,
            content_manifest=snapshot,
            trusted_config=trusted,
        )
        _emit_output(
            render_report(report, args.format, rules, verbose=args.verbose),
            args.output,
        )
        if report.get("scan_status") != "COMPLETE":
            print("Refusing to install: scan is incomplete.", file=sys.stderr)
            return 3
        if args.dry_run:
            _operation_log(args, "[dry-run] scan only; nothing installed.")
            return report["exit_code"]
        boundary_count = report["categories"].get("filesystem-boundary", 0)
        if boundary_count:
            raise ScanError("refusing to install a skill containing filesystem links")
        summary = report["summary"]
        if not args.force and summary[CRITICAL]:
            print(f"\nRefusing to install: {summary[CRITICAL]} CRITICAL finding(s).", file=sys.stderr)
            return 2
        if not args.force and summary[WARNING]:
            if not _confirm(f"{summary[WARNING]} WARNING finding(s). Install anyway?"):
                print("Aborted.", file=sys.stderr)
                return 1
        destination_name = paths.validate_skill_name(str(report["skill_name"]).strip())
        installed = _do_install(resolved.path, destination_name, snapshot)
        _operation_log(args, f"Installed '{destination_name}' to:")
        for destination in installed:
            _operation_log(args, f"   {destination}")
        return 0
    except (
        ScanError,
        baseline_mod.BaselineError,
        cache_mod.CacheError,
        cfg.ConfigError,
        manifest_mod.ManifestError,
        paths.PathSafetyError,
        semantic.SemanticError,
        OSError,
    ) as exc:
        _print_error(exc)
        return 3
    finally:
        if resolved and resolved.temporary:
            shutil.rmtree(resolved.temporary, ignore_errors=True)


def _confirm(prompt: str) -> bool:
    if not sys.stdin or not sys.stdin.isatty():
        print(prompt + " [y/N] (non-interactive -> N)", file=sys.stderr)
        return False
    try:
        print(prompt + " [y/N] ", end="", file=sys.stderr, flush=True)
        return sys.stdin.readline().strip().lower() in {"y", "yes"}
    except EOFError:
        return False


def _operation_log(args, message: str) -> None:
    stream = sys.stderr if args.format in {"json", "sarif", "markdown"} else sys.stdout
    print(manifest_mod.safe_display(message), file=stream)


def _safe_error_message(error: BaseException | str) -> str:
    message = sanitize.safe_display(error).strip()
    return message[:2000] or "operation failed"


def _print_error(error: BaseException | str) -> None:
    print(f"error: {_safe_error_message(error)}", file=sys.stderr)


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
        effect=getattr(args, "semantic_effect", "advisory"),
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
    parser.add_argument("--ref", help="remote Git branch, tag, or commit to resolve")
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
    parser.add_argument(
        "--semantic-effect",
        choices=["advisory", "dismiss"],
        default="advisory",
    )
    parser.add_argument("-v", "--verbose", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = ControlledArgumentParser(
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
    try:
        args = parser.parse_args(raw)
    except ScanError as exc:
        _print_error(exc)
        return 3
    if not args.command:
        parser.print_help()
        return 0
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    try:
        if args.command == "baseline" and args.baseline_command != "create":
            raise ScanError("baseline requires the create subcommand")
        if args.command == "lock" and args.lock_command not in {"create", "verify"}:
            raise ScanError("lock requires create or verify")
        if not hasattr(args, "fail_on"):
            raise ScanError("command is missing required scan options")
        args.fail_on = _FAIL_ON[args.fail_on]
        rules = load_rules(args.rules_dir) if args.rules_dir else load_rules()
    except (KeyError, RuleError, ScanError) as exc:
        _print_error(exc)
        return 3
    try:
        if args.command == "scan":
            if not args.all and not args.target:
                raise ScanError("scan needs a target, or --all")
            if args.all and (args.target or args.ref):
                raise ScanError("scan --all does not accept a target or --ref")
            return cmd_scan(args, rules)
        if args.command == "install":
            return cmd_install(args, rules)
        if args.command == "baseline":
            return cmd_baseline(args, rules)
        if args.command == "lock":
            return cmd_lock(args, rules)
        raise ScanError("unknown command")
    except (
        ScanError,
        archives.ArchiveError,
        baseline_mod.BaselineError,
        cache_mod.CacheError,
        cfg.ConfigError,
        installer.InstallError,
        integrity.LockError,
        manifest_mod.ManifestError,
        paths.PathSafetyError,
        RuleError,
        semantic.SemanticError,
        target_mod.TargetError,
        OSError,
        UnicodeError,
        RecursionError,
    ) as exc:
        _print_error(exc)
        return 3
