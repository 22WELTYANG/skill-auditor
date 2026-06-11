#!/usr/bin/env python3
"""
skill-auditor / scan.py — deterministic security scanner for Agent skills.

Layer 1 of skill-auditor. Loads the rule catalog from ../rules/*.yaml (single
source of truth — see rules_loader.py) and scans every text file in a skill.

Two kinds of rule:
  - deterministic : regex hit == a real finding (exfiltration, dangerous shell,
                    credential read, obfuscation).
  - semantic      : the regex is only a *pre-filter*. The hit is reported with
                    `needs_semantic_review: true` and `guidance`, for the agent
                    to judge intent in SKILL.md (prompt injection, logic bombs,
                    description-vs-behavior mismatch).

Both kinds appear in one JSON report and count toward one verdict; the agent
layer can later downgrade false positives.

Usage:
    python scan.py <skill-dir | github-url> [--format json|text]
                   [--min-severity INFO|WARNING|CRITICAL] [--rules-dir DIR]

Exit code: 0 safe · 1 review · 2 do-not-install · 3 scan error.
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

VERSION = "0.2.0"

TEXT_SUFFIXES = {
    ".md", ".markdown", ".txt", ".sh", ".bash", ".zsh", ".fish",
    ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php",
    ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".env",
    ".ps1", ".bat", ".cmd", "",
}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".idea"}
MAX_BYTES = 1_000_000

# Categories whose CRITICAL findings make a benign-looking description a lie.
_MISMATCH_TRIGGER_CATS = {
    "data-exfiltration", "credential-read", "dangerous-shell", "obfuscation",
}
_MISMATCH_SENSITIVE_TERMS = (
    "secret", "credential", "password", "token", "ssh", "aws", "exfiltrat",
    "upload your", "send your", "steal", "private key", "delete", "rm -rf",
    "network", "remote server",
)


# --------------------------------------------------------------------------- #
# File discovery
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
# Frontmatter (minimal, only what mismatch detection needs)
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
def make_finding(rule: dict, file: str, line: int, snippet: str) -> dict:
    semantic = rule["layer"] == "semantic"
    guidance = rule.get("guidance") or ""
    return {
        # new (round 2)
        "rule_id": rule["id"],
        "layer": rule["layer"],
        "rationale": rule.get("rationale") or "",
        "guidance": guidance,
        "needs_semantic_review": semantic,
        # kept for back-compat with round-1 consumers
        "id": rule["id"],
        "category": rule["category"],
        "severity": rule["severity"],
        "file": file,
        "line": line,
        "snippet": snippet,
        "explanation": rule.get("rationale") or "",
        "recommendation": guidance or "Review this finding before trusting the skill.",
    }


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #
def scan_repo(root: Path, rules: list[dict]) -> tuple[list[Path], list[dict]]:
    files = gather_files(root)
    line_rules = [r for r in rules if r.get("_regex") and not r.get("check")]
    findings: list[dict] = []

    for path in files:
        rel = str(path.relative_to(root)).replace("\\", "/")
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for rule in line_rules:
                if rule["_regex"].search(line):
                    findings.append(make_finding(rule, rel, lineno, snippet_of(line)))

    # built-in cross-file checks
    for rule in rules:
        if rule.get("check") == "description-mismatch":
            findings.extend(check_description_mismatch(root, findings, rule))
    return files, findings


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
    })
    if not (benign and serious):
        return []

    f = make_finding(
        rule,
        str(skill_md.relative_to(root)).replace("\\", "/"),
        desc_line or 1,
        snippet_of("description: " + (fm.get("description") or "")),
    )
    f["guidance"] = (f["guidance"] + f"  Observed high-risk behavior: {', '.join(serious)}.").strip()
    f["recommendation"] = f["guidance"]
    return [f]


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


def verdict_for(summary: dict) -> tuple[str, str, int]:
    if summary[CRITICAL] > 0:
        return "DO_NOT_INSTALL", "DO NOT INSTALL", 2
    if summary[WARNING] > 0:
        return "REVIEW_BEFORE_INSTALL", "REVIEW BEFORE INSTALL", 1
    return "SAFE_TO_INSTALL", "SAFE TO INSTALL", 0


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def render_text(report: dict) -> str:
    colors = sys.stdout.isatty()

    def c(code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if colors else s

    sev_color = {CRITICAL: "1;31", WARNING: "1;33", INFO: "1;36"}
    s = report["summary"]
    out = [
        "=" * 64,
        f" skill-auditor v{report['version']} - scan report",
        f" target : {report['target']}",
        f" files  : {len(report['scanned_files'])} scanned   rules: {report['rules_loaded']}",
        f" totals : {c('1;31', str(s[CRITICAL]) + ' CRITICAL')}  "
        f"{c('1;33', str(s[WARNING]) + ' WARNING')}  "
        f"{c('1;36', str(s[INFO]) + ' INFO')}   "
        f"({s['needs_semantic_review']} need semantic review)",
        "=" * 64,
    ]
    if not report["findings"]:
        out += ["", "  No risk patterns matched. (Layer 1 only — still have the",
                "  agent semantically review SKILL.md before trusting it.)", ""]
    for f in report["findings"]:
        tag = c(sev_color.get(f["severity"], "0"), f"[{f['severity']}]")
        mark = "  ~semantic" if f["needs_semantic_review"] else ""
        out.append(f"\n{tag} {f['category']}  ({f['rule_id']}){mark}")
        out.append(f"  {f['file']}:{f['line']}")
        out.append(f"    > {f['snippet']}")
        out.append(f"    why: {f['rationale']}")
        if f["needs_semantic_review"] and f["guidance"]:
            out.append(f"    review: {f['guidance']}")
    out += ["", "=" * 64, f" VERDICT: {report['verdict_label']}", "=" * 64]
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="scan.py",
        description="Deterministic security scanner for Agent skills (skill-auditor).",
    )
    ap.add_argument("target", help="path to a skill directory, or a GitHub repo URL")
    ap.add_argument("--format", choices=["json", "text"], default="json")
    ap.add_argument("--min-severity", choices=[INFO, WARNING, CRITICAL], default=INFO)
    ap.add_argument("--rules-dir", default=str(rl.DEFAULT_RULES_DIR),
                    help="directory of rule YAML files (default: ../rules)")
    ap.add_argument("--version", action="version", version=f"skill-auditor {VERSION}")
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    try:
        rules = rl.load_rules(args.rules_dir)
    except rl.RuleError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3

    try:
        root, tmp = resolve_target(args.target)
    except SystemExit as e:
        print(e, file=sys.stderr)
        return 3

    try:
        files, findings = scan_repo(root, rules)

        floor = SEVERITY_RANK[args.min_severity]
        findings = [f for f in findings if SEVERITY_RANK[f["severity"]] >= floor]
        findings.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]],
                                     rl._cat_index(f["category"]), f["file"], f["line"]))

        summary = {
            CRITICAL: sum(1 for f in findings if f["severity"] == CRITICAL),
            WARNING: sum(1 for f in findings if f["severity"] == WARNING),
            INFO: sum(1 for f in findings if f["severity"] == INFO),
            "total": len(findings),
            "needs_semantic_review": sum(1 for f in findings if f["needs_semantic_review"]),
        }
        categories = {}
        for f in findings:
            categories[f["category"]] = categories.get(f["category"], 0) + 1
        verdict_code, verdict_label, exit_code = verdict_for(summary)

        report = {
            "tool": "skill-auditor",
            "version": VERSION,
            "target": args.target,
            "rules_loaded": len(rules),
            "scanned_files": [str(p.relative_to(root)).replace("\\", "/") for p in files],
            "summary": summary,
            "categories": categories,
            "findings": findings,
            "verdict": verdict_code,
            "verdict_label": verdict_label,
        }

        if args.format == "json":
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            print(render_text(report))
        return exit_code
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
