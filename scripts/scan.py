#!/usr/bin/env python3
"""
skill-auditor / scan.py — deterministic scanner + install gate for Agent skills.

Layer 1 of skill-auditor. Loads the rule catalog from ../rules/*.yaml (single
source of truth — see rules_loader.py) and scans every text file in a skill.

Two kinds of rule:
  - deterministic : regex hit == a real finding (exfiltration, dangerous shell,
                    credential read, obfuscation).
  - semantic      : the regex is only a *pre-filter*. The hit is reported with
                    `needs_semantic_review: true`, `guidance`, and a few lines of
                    `context`, for the agent to judge intent in SKILL.md (prompt
                    injection, logic bombs, description-vs-behavior mismatch).

False-positive control (config.py) runs before the report: a built-in domain
allowlist, project `.skill-auditor.yml`, and inline `# skill-auditor: ignore`
comments. Suppressed findings are kept (with a reason) and shown under
--verbose, never silently dropped.

Subcommands:
    scan     <dir|url>     scan one skill   (or `--all` for every installed skill)
    install  <dir|url>     scan, then gate the install on the result

Back-compat: `scan.py <dir|url> [flags]` with no subcommand still scans.

Exit code is driven by --fail-on: 0 if nothing reaches the threshold, else
nonzero (2 if any CRITICAL, else 1). 3 on scan error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import rules_loader as rl  # noqa: E402
from rules_loader import CRITICAL, WARNING, INFO, SEVERITY_RANK  # noqa: E402
import config as cfg  # noqa: E402
import formats  # noqa: E402
import paths  # noqa: E402

VERSION = "0.3.0"

TEXT_SUFFIXES = {
    ".md", ".markdown", ".txt", ".sh", ".bash", ".zsh", ".fish",
    ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php",
    ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".env",
    ".ps1", ".bat", ".cmd", "",
}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".idea"}
MAX_BYTES = 1_000_000
CONTEXT_LINES = 3  # lines of context handed to the semantic layer

_MISMATCH_TRIGGER_CATS = {
    "data-exfiltration", "credential-read", "dangerous-shell", "obfuscation",
}
_MISMATCH_SENSITIVE_TERMS = (
    "secret", "credential", "password", "token", "ssh", "aws", "exfiltrat",
    "upload your", "send your", "steal", "private key", "delete", "rm -rf",
    "network", "remote server",
)


# --------------------------------------------------------------------------- #
# File discovery (text only, size-capped)
# --------------------------------------------------------------------------- #
def is_probably_text(path: Path) -> bool:
    if path.suffix.lower() not in TEXT_SUFFIXES:
        return False
    try:
        if path.stat().st_size > MAX_BYTES:
            return False
        with path.open("rb") as fh:
            return b"\x00" not in fh.read(4096)
    except OSError:
        return False


def gather_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            if is_probably_text(p):
                files.append(p)
    return sorted(files)


# --------------------------------------------------------------------------- #
# Frontmatter (only what mismatch detection needs)
# --------------------------------------------------------------------------- #
def parse_frontmatter(text: str) -> tuple[dict[str, str], int]:
    out: dict[str, str] = {}
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return out, 0
    key = None
    buf: list[str] = []
    desc_line = 0
    for i, line in enumerate(lines[1:], start=2):
        if line.strip() == "---":
            break
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if m and not line.startswith((" ", "\t")):
            if key is not None:
                out[key] = " ".join(buf).strip().strip("'\"")
            key = m.group(1).lower()
            buf = [m.group(2)]
            if key == "description":
                desc_line = i
        else:
            buf.append(line.strip())
    if key is not None:
        out[key] = " ".join(buf).strip().strip("'\"")
    return out, desc_line


def snippet_of(line: str, limit: int = 200) -> str:
    s = line.strip()
    return s if len(s) <= limit else s[:limit] + " ..."


# --------------------------------------------------------------------------- #
# Finding construction (back-compatible JSON shape + new fields)
# --------------------------------------------------------------------------- #
def _confidence_for(rule: dict) -> str:
    if rule.get("confidence"):
        return rule["confidence"]
    # deterministic regex hits are exact; semantic hits are pre-filters.
    return "high" if rule["layer"] == "deterministic" else "medium"


def make_finding(rule: dict, file: str, line: int, snippet: str,
                 context: list[str] | None = None) -> dict:
    semantic = rule["layer"] == "semantic"
    guidance = rule.get("guidance") or ""
    f = {
        # round-2 fields
        "rule_id": rule["id"],
        "layer": rule["layer"],
        "rationale": rule.get("rationale") or "",
        "guidance": guidance,
        "needs_semantic_review": semantic,
        # round-3 fields
        "confidence": _confidence_for(rule),
        "suppressed": False,
        "suppressed_reason": None,
        "context": context if semantic else None,
        # back-compat (round-1)
        "id": rule["id"],
        "category": rule["category"],
        "severity": rule["severity"],
        "file": file,
        "line": line,
        "snippet": snippet,
        "explanation": rule.get("rationale") or "",
        "recommendation": guidance or "Review this finding before trusting the skill.",
    }
    return f


def _context_window(lines: list[str], idx0: int) -> list[str]:
    lo = max(0, idx0 - CONTEXT_LINES)
    hi = min(len(lines), idx0 + CONTEXT_LINES + 1)
    return [f"{n + 1}: {lines[n]}" for n in range(lo, hi)]


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #
def scan_repo(root: Path, rules: list[dict], config: cfg.Config) -> tuple[list[Path], list[dict]]:
    files = gather_files(root)
    line_rules = [r for r in rules if r.get("_regex") and not r.get("check")]
    findings: list[dict] = []
    line_index: dict[tuple[str, int], str] = {}  # (file,line) -> raw line text

    for path in files:
        rel = str(path.relative_to(root)).replace("\\", "/")
        if config.is_ignored_path(rel):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        all_lines = text.splitlines()
        for lineno, line in enumerate(all_lines, start=1):
            line_index[(rel, lineno)] = line
            for rule in line_rules:
                if rule["_regex"].search(line):
                    ctx = (_context_window(all_lines, lineno - 1)
                           if rule["layer"] == "semantic" else None)
                    findings.append(make_finding(rule, rel, lineno,
                                                 snippet_of(line), ctx))

    # built-in cross-file checks
    for rule in rules:
        if rule.get("check") == "description-mismatch":
            extra = check_description_mismatch(root, findings, rule)
            for f in extra:
                line_index.setdefault((f["file"], f["line"]), f["snippet"])
            findings.extend(extra)

    _apply_suppression(findings, line_index, config)
    return files, findings


def _apply_suppression(findings: list[dict], line_index: dict, config: cfg.Config) -> None:
    for f in findings:
        line_text = line_index.get((f["file"], f["line"]), f.get("snippet", ""))
        reason = config.suppression_reason(f, line_text)
        if reason:
            f["suppressed"] = True
            f["suppressed_reason"] = reason


def check_description_mismatch(root: Path, findings: list[dict], rule: dict) -> list[dict]:
    skill_md = root / "SKILL.md"
    if not skill_md.exists():
        for p in root.iterdir():
            if p.is_file() and p.name.lower() == "skill.md":
                skill_md = p
                break
    if not skill_md.exists():
        return []

    text = skill_md.read_text(encoding="utf-8", errors="replace")
    fm, desc_line = parse_frontmatter(text)
    description = (fm.get("description") or "").lower()
    if not description:
        return []

    benign = not any(term in description for term in _MISMATCH_SENSITIVE_TERMS)
    serious = sorted({
        f["category"] for f in findings
        if f["severity"] == CRITICAL and f["category"] in _MISMATCH_TRIGGER_CATS
        and not f.get("suppressed")
    })
    if not (benign and serious):
        return []

    f = make_finding(
        rule,
        str(skill_md.relative_to(root)).replace("\\", "/"),
        desc_line or 1,
        snippet_of("description: " + (fm.get("description") or "")),
        context=[f"description: {fm.get('description', '')}"],
    )
    f["guidance"] = (f["guidance"] + f"  Observed high-risk behavior: {', '.join(serious)}.").strip()
    f["recommendation"] = f["guidance"]
    return [f]


# --------------------------------------------------------------------------- #
# Reproducible ordering + de-dup
# --------------------------------------------------------------------------- #
def _sort_key(f: dict):
    return (-SEVERITY_RANK[f["severity"]], rl._cat_index(f["category"]),
            f["file"], f["line"], f["rule_id"])


def normalize(findings: list[dict]) -> list[dict]:
    """Stable sort by (severity, category, file, line, rule_id) and drop exact
    duplicates, so two scans of the same input diff cleanly."""
    seen: set[tuple] = set()
    unique: list[dict] = []
    for f in sorted(findings, key=_sort_key):
        key = (f["rule_id"], f["file"], f["line"], f["snippet"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique


# --------------------------------------------------------------------------- #
# Target resolution (local dir or GitHub URL)
# --------------------------------------------------------------------------- #
def resolve_target(target: str) -> tuple[Path, str | None]:
    if re.match(r"^(https?://|git@)", target) or target.startswith("github.com/"):
        url = target if not target.startswith("github.com/") else "https://" + target
        tmp = tempfile.mkdtemp(prefix="skill-auditor-")
        try:
            subprocess.run(["git", "clone", "--depth", "1", url, tmp],
                           check=True, capture_output=True, text=True)
        except FileNotFoundError:
            shutil.rmtree(tmp, ignore_errors=True)
            raise SystemExit("error: git is not installed but a URL was given.")
        except subprocess.CalledProcessError as e:
            shutil.rmtree(tmp, ignore_errors=True)
            raise SystemExit(f"error: git clone failed:\n{e.stderr}")
        return Path(tmp), tmp
    p = Path(target).expanduser()
    if not p.exists():
        raise SystemExit(f"error: path does not exist: {target}")
    return p, None


# --------------------------------------------------------------------------- #
# Verdict + exit code
# --------------------------------------------------------------------------- #
def verdict_for(summary: dict) -> tuple[str, str]:
    if summary[CRITICAL] > 0:
        return "DO_NOT_INSTALL", "DO NOT INSTALL"
    if summary[WARNING] > 0:
        return "REVIEW_BEFORE_INSTALL", "REVIEW BEFORE INSTALL"
    return "SAFE_TO_INSTALL", "SAFE TO INSTALL"


def exit_code_for(summary: dict, fail_on: str) -> int:
    floor = SEVERITY_RANK[fail_on]
    fails = any(summary[s] > 0 and SEVERITY_RANK[s] >= floor
                for s in (CRITICAL, WARNING, INFO))
    if not fails:
        return 0
    return 2 if summary[CRITICAL] > 0 else 1


# --------------------------------------------------------------------------- #
# Build a report for one skill
# --------------------------------------------------------------------------- #
def build_report(target: str, root: Path, rules: list[dict], *,
                 min_severity: str, fail_on: str) -> dict:
    config = cfg.load_config(root)
    files, findings = scan_repo(root, rules, config)

    floor = SEVERITY_RANK[min_severity]
    findings = [f for f in findings if SEVERITY_RANK[f["severity"]] >= floor]
    findings = normalize(findings)

    active = [f for f in findings if not f["suppressed"]]
    suppressed = [f for f in findings if f["suppressed"]]

    summary = {
        CRITICAL: sum(1 for f in active if f["severity"] == CRITICAL),
        WARNING: sum(1 for f in active if f["severity"] == WARNING),
        INFO: sum(1 for f in active if f["severity"] == INFO),
        "total": len(active),
        "needs_semantic_review": sum(1 for f in active if f["needs_semantic_review"]),
        "suppressed": len(suppressed),
    }
    categories: dict[str, int] = {}
    for f in active:
        categories[f["category"]] = categories.get(f["category"], 0) + 1
    verdict_code, verdict_label = verdict_for(summary)

    return {
        "tool": "skill-auditor",
        "version": VERSION,
        "target": target,
        "rules_loaded": len(rules),
        "fail_on": fail_on,
        "config_source": config.source,
        "scanned_files": [str(p.relative_to(root)).replace("\\", "/") for p in files],
        "summary": summary,
        "categories": categories,
        "findings": active,
        "suppressed": suppressed,
        "verdict": verdict_code,
        "verdict_label": verdict_label,
        "exit_code": exit_code_for(summary, fail_on),
    }


def render_report(report: dict, fmt: str, rules: list[dict], *, verbose: bool) -> str:
    if fmt in ("pretty", "text"):
        return formats.render_pretty(report, verbose=verbose)
    if fmt == "json":
        return formats.render_json(report)
    if fmt == "markdown":
        return formats.render_markdown(report)
    if fmt == "sarif":
        return formats.render_sarif(report, rules)
    raise ValueError(f"unknown format: {fmt}")


# --------------------------------------------------------------------------- #
# Subcommand: scan
# --------------------------------------------------------------------------- #
def cmd_scan(args, rules: list[dict]) -> int:
    if args.all:
        return _scan_all(args, rules)

    try:
        root, tmp = resolve_target(args.target)
    except SystemExit as e:
        print(e, file=sys.stderr)
        return 3
    try:
        report = build_report(args.target, root, rules,
                              min_severity=args.min_severity, fail_on=args.fail_on)
        print(render_report(report, args.format, rules, verbose=args.verbose))
        return report["exit_code"]
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


def _scan_all(args, rules: list[dict]) -> int:
    skills = paths.installed_skills()
    if not skills:
        print("No installed skills found under "
              + ", ".join(str(d) for d in paths.search_dirs()), file=sys.stderr)
        return 0

    reports = []
    for skill in skills:
        reports.append(build_report(str(skill), skill, rules,
                                    min_severity=args.min_severity, fail_on=args.fail_on))

    if args.format == "json":
        print(json.dumps({"tool": "skill-auditor", "version": VERSION,
                          "scanned": len(reports), "reports": reports},
                         indent=2, ensure_ascii=False))
    elif args.format == "sarif":
        # one SARIF run with results merged across skills
        merged = {"version": VERSION, "scanned_files": [],
                  "findings": [f for r in reports for f in r["findings"]]}
        print(formats.render_sarif(merged, rules))
    else:
        print(_summary_table(reports))

    worst = max((r["exit_code"] for r in reports), default=0)
    return worst


def _summary_table(reports: list[dict]) -> str:
    name_w = max([len("SKILL")] + [len(Path(r["target"]).name) for r in reports])
    out = [
        "=" * 64,
        f" skill-auditor v{VERSION} — audit of {len(reports)} installed skill(s)",
        "=" * 64,
        f" {'SKILL'.ljust(name_w)}  {'CRIT':>4} {'WARN':>4} {'INFO':>4}  VERDICT",
        f" {'-' * name_w}  ---- ---- ----  -------",
    ]
    for r in sorted(reports, key=lambda r: (-r["summary"][CRITICAL],
                                            -r["summary"][WARNING], r["target"])):
        s = r["summary"]
        out.append(f" {Path(r['target']).name.ljust(name_w)}  "
                   f"{s[CRITICAL]:>4} {s[WARNING]:>4} {s[INFO]:>4}  "
                   f"{formats.VERDICT_EMOJI.get(r['verdict'], '')} {r['verdict_label']}")
    blocked = sum(1 for r in reports if r["exit_code"] != 0)
    out += ["=" * 64,
            f" {blocked} of {len(reports)} skill(s) exceed the fail-on threshold "
            f"({reports[0]['fail_on'] if reports else 'critical'})",
            "=" * 64]
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Subcommand: install (scan, then gate)
# --------------------------------------------------------------------------- #
def cmd_install(args, rules: list[dict]) -> int:
    try:
        root, tmp = resolve_target(args.target)
    except SystemExit as e:
        print(e, file=sys.stderr)
        return 3
    try:
        report = build_report(args.target, root, rules,
                              min_severity=INFO, fail_on=args.fail_on)
        print(render_report(report, args.format, rules, verbose=args.verbose))
        s = report["summary"]

        if args.dry_run:
            print("\n[dry-run] scan only; nothing installed.")
            return report["exit_code"]

        if not args.force:
            if s[CRITICAL] > 0:
                print(f"\n⛔ Refusing to install: {s[CRITICAL]} CRITICAL finding(s). "
                      "Re-run with --force only if you are certain.", file=sys.stderr)
                return 2
            if s[WARNING] > 0:
                if not _confirm(f"\n⚠️  {s[WARNING]} WARNING finding(s). Install anyway?"):
                    print("Aborted.", file=sys.stderr)
                    return 1

        dest_name = _skill_name(root)
        installed = _do_install(root, dest_name)
        print(f"\n✅ Installed '{dest_name}' to:")
        for d in installed:
            print(f"   {d}")
        return 0
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


def _confirm(prompt: str) -> bool:
    if not sys.stdin or not sys.stdin.isatty():
        # non-interactive: default to No (safe)
        print(prompt + " [y/N] (non-interactive → N)")
        return False
    try:
        return input(prompt + " [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


def _skill_name(root: Path) -> str:
    name = root.name
    if name.startswith("skill-auditor-"):  # temp clone dir → read SKILL.md name
        skill_md = root / "SKILL.md"
        if skill_md.is_file():
            fm, _ = parse_frontmatter(skill_md.read_text(encoding="utf-8", errors="replace"))
            if fm.get("name"):
                return re.sub(r"[^A-Za-z0-9._-]", "-", fm["name"])
    return name


def _do_install(root: Path, dest_name: str) -> list[Path]:
    installed = []
    for parent in paths.install_targets():
        dest = parent / dest_name
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        shutil.copytree(root, dest, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        installed.append(dest)
    return installed


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--format", choices=["pretty", "json", "sarif", "markdown", "text"],
                   default="pretty", help="output format (default: pretty; 'text' = pretty)")
    p.add_argument("--fail-on", choices=["critical", "warning", "info"], default="critical",
                   help="severity that makes the run fail / exit nonzero (default: critical)")
    p.add_argument("--min-severity", choices=[INFO, WARNING, CRITICAL], default=INFO,
                   help="drop findings below this severity from the report")
    p.add_argument("--rules-dir", default=str(rl.DEFAULT_RULES_DIR))
    p.add_argument("-v", "--verbose", action="store_true",
                   help="also list suppressed findings")


# argparse stores --fail-on as critical/warning/info; map to rank keys.
_FAILON_TO_SEV = {"critical": CRITICAL, "warning": WARNING, "info": INFO}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="skill-auditor",
        description="Scan an Agent skill for security risks — and gate installs on the result.",
    )
    ap.add_argument("--version", action="version", version=f"skill-auditor {VERSION}")
    sub = ap.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="scan a skill (or --all installed skills)")
    p_scan.add_argument("target", nargs="?", help="skill dir or GitHub URL")
    p_scan.add_argument("--all", action="store_true",
                        help="scan every installed skill under the known skill dirs")
    _add_common(p_scan)

    p_inst = sub.add_parser("install", help="scan a skill, then install it if it passes the gate")
    p_inst.add_argument("target", help="skill dir or GitHub URL")
    p_inst.add_argument("--force", action="store_true", help="skip the gate and install anyway")
    p_inst.add_argument("--dry-run", action="store_true", help="scan only; do not install")
    _add_common(p_inst)
    return ap


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    # Back-compat: bare `scan.py <target> [flags]` with no subcommand → scan.
    if raw and raw[0] not in ("scan", "install", "-h", "--help", "--version"):
        raw = ["scan"] + raw

    ap = build_parser()
    args = ap.parse_args(raw)
    if not getattr(args, "command", None):
        ap.print_help()
        return 0

    # normalize fail-on to a severity rank key
    args.fail_on = _FAILON_TO_SEV[args.fail_on]

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    try:
        rules = rl.load_rules(args.rules_dir)
    except rl.RuleError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3

    if args.command == "scan":
        if not args.all and not args.target:
            print("error: scan needs a target, or --all", file=sys.stderr)
            return 3
        return cmd_scan(args, rules)
    if args.command == "install":
        return cmd_install(args, rules)
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
