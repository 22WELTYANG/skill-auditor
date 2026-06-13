#!/usr/bin/env python3
"""Reproducible, metadata-only public Skill corpus research pipeline."""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import shutil
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from skill_auditor import cli, identity  # noqa: E402
from skill_auditor.rules_loader import CRITICAL, INFO, load_rules  # noqa: E402

API = "https://api.github.com"
DEFAULT_QUERIES = (
    "topic:agent-skills",
    "topic:claude-skills",
    "topic:codex-skills",
    "topic:cursor-rules",
    '"SKILL.md" AI agent in:readme',
)
MAX_MEMBERS = 100_000
MAX_EXPANDED_BYTES = 1_000_000_000
MAX_DOWNLOAD_BYTES = 500_000_000


class ResearchError(ValueError):
    pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    discover = commands.add_parser("discover")
    discover.add_argument("--output", required=True)
    discover.add_argument("--limit", type=int, default=500)
    discover.add_argument("--query", action="append")
    scan = commands.add_parser("scan")
    scan.add_argument("--manifest", required=True)
    scan.add_argument("--output", required=True)
    scan.add_argument("--limit", type=int, default=500)
    stats = commands.add_parser("stats")
    stats.add_argument("--results", required=True)
    stats.add_argument("--output", required=True)
    sample = commands.add_parser("sample")
    sample.add_argument("--results", required=True)
    sample.add_argument("--output", required=True)
    sample.add_argument("--size", type=int, default=1000)
    sample.add_argument("--double-review", type=float, default=0.20)
    args = parser.parse_args(argv)
    try:
        if args.command == "discover":
            payload = discover_repositories(args.query or DEFAULT_QUERIES, args.limit)
        elif args.command == "scan":
            payload = scan_manifest(Path(args.manifest), args.limit)
        elif args.command == "stats":
            payload = build_statistics(_read_json(Path(args.results)))
        else:
            payload = build_label_sample(
                _read_json(Path(args.results)),
                args.size,
                args.double_review,
            )
        _write_json(Path(args.output), payload)
        return 0
    except (ResearchError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3


def discover_repositories(queries, limit: int) -> dict:
    if limit < 1:
        raise ResearchError("limit must be positive")
    repositories: dict[str, dict] = {}
    for query in queries:
        page = 1
        while len(repositories) < limit and page <= 10:
            data = _github_json(
                "/search/repositories?"
                + urllib.parse.urlencode({
                    "q": query,
                    "sort": "updated",
                    "order": "desc",
                    "per_page": 100,
                    "page": page,
                })
            )
            items = data.get("items") or []
            if not items:
                break
            for item in items:
                full_name = item["full_name"]
                if full_name in repositories:
                    continue
                branch = item.get("default_branch") or "main"
                commit = _github_json(
                    f"/repos/{full_name}/commits/{urllib.parse.quote(branch, safe='')}"
                )
                repositories[full_name] = {
                    "repository": full_name,
                    "html_url": item.get("html_url"),
                    "commit": commit["sha"],
                    "default_branch": branch,
                    "license": (item.get("license") or {}).get("spdx_id"),
                    "archived": bool(item.get("archived")),
                    "fork": bool(item.get("fork")),
                    "discovery_query": query,
                }
                if len(repositories) >= limit:
                    break
            page += 1
    return {
        "schema": "skill-auditor-corpus-manifest/v1",
        "repository_count": len(repositories),
        "repositories": sorted(
            repositories.values(), key=lambda item: item["repository"].lower()
        ),
    }


def scan_manifest(path: Path, limit: int) -> dict:
    manifest = _read_json(path)
    repositories = (manifest.get("repositories") or [])[:limit]
    rules = load_rules()
    results = []
    errors = []
    for repository in repositories:
        full_name = repository["repository"]
        commit = repository["commit"]
        temporary = Path(tempfile.mkdtemp(prefix="skill-auditor-corpus-"))
        try:
            archive = _github_bytes(
                f"/repos/{full_name}/tarball/{commit}",
                max_bytes=MAX_DOWNLOAD_BYTES,
            )
            root = _extract_tarball(archive, temporary)
            try:
                report = cli.build_recursive_report(
                    full_name,
                    root,
                    rules,
                    min_severity=INFO,
                    fail_on=CRITICAL,
                    source_root=root,
                    use_cache=False,
                )
            except cli.ScanError as exc:
                if "found no valid SKILL.md roots" in str(exc):
                    continue
                raise
            for skill_report in report["reports"]:
                for finding in skill_report["findings"]:
                    results.append({
                        "repository": full_name,
                        "commit": commit,
                        "license": repository.get("license"),
                        "skill": skill_report["target"],
                        "rule_id": finding["rule_id"],
                        "severity": finding["severity"],
                        "category": finding["category"],
                        "fingerprint": finding["fingerprint"],
                        "artifact_uri": finding["artifact_uri"],
                        "line": finding["line"],
                        "needs_semantic_review": finding["needs_semantic_review"],
                    })
        except Exception as exc:
            errors.append({
                "repository": full_name,
                "commit": commit,
                "error": str(exc)[:500],
            })
        finally:
            shutil.rmtree(temporary, ignore_errors=True)
    return {
        "schema": "skill-auditor-corpus-results/v1",
        "scanner_version": cli.VERSION,
        "rules_digest": identity.rules_digest(rules),
        "repositories_requested": len(repositories),
        "finding_count": len(results),
        "findings": results,
        "errors": errors,
    }


def build_statistics(results: dict) -> dict:
    findings = results.get("findings") or []
    repositories = {item["repository"] for item in findings}
    skills = {(item["repository"], item["skill"]) for item in findings}
    by_rule = Counter(item["rule_id"] for item in findings)
    by_category = Counter(item["category"] for item in findings)
    labels = results.get("labels") or []
    label_by_rule: dict[str, Counter] = defaultdict(Counter)
    for item in labels:
        label_by_rule[item["rule_id"]][item["label"]] += 1
    precision = {}
    for rule_id, counts in sorted(label_by_rule.items()):
        reviewed = counts["true_positive"] + counts["false_positive"]
        true_positive = counts["true_positive"]
        low, high = wilson_interval(true_positive, reviewed)
        precision[rule_id] = {
            "reviewed": reviewed,
            "precision": true_positive / reviewed if reviewed else None,
            "wilson_95": [low, high],
            "uncertain": counts["uncertain"],
        }
    return {
        "schema": "skill-auditor-corpus-statistics/v1",
        "repository_count_with_findings": len(repositories),
        "skill_count_with_findings": len(skills),
        "finding_count": len(findings),
        "findings_by_rule": dict(sorted(by_rule.items())),
        "findings_by_category": dict(sorted(by_category.items())),
        "precision_by_rule": precision,
    }


def build_label_sample(results: dict, size: int, double_review: float) -> dict:
    if size < 1 or not 0 <= double_review <= 1:
        raise ResearchError("invalid sample size or double-review ratio")
    unique = {}
    for item in results.get("findings") or []:
        unique.setdefault(item["fingerprint"], item)
    strata: dict[str, list[dict]] = defaultdict(list)
    for item in unique.values():
        strata[item["rule_id"]].append(item)
    rng = random.Random(0)
    selected = []
    while len(selected) < min(size, len(unique)) and strata:
        for rule_id in sorted(list(strata)):
            values = strata[rule_id]
            if not values:
                del strata[rule_id]
                continue
            item = values.pop(rng.randrange(len(values)))
            selected.append({
                **item,
                "label": None,
                "reviewer_1": None,
                "reviewer_2": None,
                "double_review": False,
            })
            if len(selected) >= min(size, len(unique)):
                break
    double_count = math.ceil(len(selected) * double_review)
    for item in rng.sample(selected, k=double_count) if double_count else []:
        item["double_review"] = True
    return {
        "schema": "skill-auditor-label-sample/v1",
        "sample_size": len(selected),
        "double_review_count": double_count,
        "items": selected,
    }


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> tuple[float | None, float | None]:
    if total <= 0:
        return None, None
    proportion = successes / total
    denominator = 1 + z * z / total
    centre = (proportion + z * z / (2 * total)) / denominator
    margin = (
        z
        * math.sqrt(
            proportion * (1 - proportion) / total
            + z * z / (4 * total * total)
        )
        / denominator
    )
    return max(0.0, centre - margin), min(1.0, centre + margin)


def _extract_tarball(raw: bytes, destination: Path) -> Path:
    total = 0
    top_levels = set()
    with tarfile.open(fileobj=__import__("io").BytesIO(raw), mode="r:*") as handle:
        members = handle.getmembers()
        if len(members) > MAX_MEMBERS:
            raise ResearchError("repository tarball contains too many members")
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise ResearchError("repository tarball contains an unsafe path")
            if path.parts:
                top_levels.add(path.parts[0])
            if member.issym() or member.islnk() or member.isdev():
                continue
            target = destination.joinpath(*path.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            total += member.size
            if total > MAX_EXPANDED_BYTES:
                raise ResearchError("repository tarball exceeds extraction limit")
            source = handle.extractfile(member)
            if source is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as output:
                shutil.copyfileobj(source, output)
    if len(top_levels) != 1:
        raise ResearchError("repository tarball has an unexpected root layout")
    return destination / next(iter(top_levels))


def _github_json(path: str) -> dict:
    return json.loads(_github_bytes(path).decode("utf-8"))


def _github_bytes(path: str, max_bytes: int = 20_000_000) -> bytes:
    token = os.environ.get("GITHUB_TOKEN", "")
    request = urllib.request.Request(
        API + path,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "skill-auditor-research",
            **({"Authorization": f"Bearer {token}"} if token else {}),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            length = response.headers.get("Content-Length")
            if length and int(length) > max_bytes:
                raise ResearchError("GitHub response exceeds the download limit")
            chunks = []
            total = 0
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    raise ResearchError("GitHub response exceeds the download limit")
                chunks.append(chunk)
            return b"".join(chunks)
    except OSError as exc:
        raise ResearchError(f"GitHub API request failed: {exc}") from exc


def _read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ResearchError("input JSON must be an object")
    return value


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


if __name__ == "__main__":
    raise SystemExit(main())
