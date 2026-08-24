[简体中文](ci-ecosystem.zh-CN.md)

# CI and trust infrastructure

## GitHub Action

Pin an exact release or full commit SHA for reproducible audits:

```yaml
permissions:
  contents: read
  security-events: write
  actions: read

steps:
  - uses: actions/checkout@<FULL_COMMIT_SHA> # pin the reviewed checkout release
    with:
      fetch-depth: 0
  - uses: 22WELTYANG/skill-auditor@<REVIEWED_V0_9_0_COMMIT_SHA>
    with:
      path: .
      recursive: "true"
      baseline: auto
      artifact-name: skill-auditor-report
      sarif-category: skill-auditor
```

`action.yml` is a same-repository Composite Action. It installs the package
from `GITHUB_ACTION_PATH`, scans without executing target content, writes JSON
and SARIF under `RUNNER_TEMP`, uploads both reports, and applies the scan exit
code last. Invalid Action inputs produce a controlled `ERROR` with exit code
`3`, not a traceback. Artifact upload is non-fatal; repositories without GitHub
Code Security may also leave SARIF upload enabled because that step is
non-fatal and the scanner gate still runs.

Use `artifact-name` when multiple scans in one job would otherwise collide. Use
`sarif-category` to give each Code Scanning analysis a stable, distinct
category.

## Pull-request trust boundary

On pull requests, `config` and explicit `baseline` paths are read with
`git show` from the base commit. `baseline: auto` expands a guarded `git
archive` of the base commit and scans the same input path. Links, devices,
traversal paths, oversized archives, and excessive member counts are rejected.
Untrusted PR-head files cannot define their own suppression or baseline policy.

## SARIF identity

Each Skill produces one SARIF run with a stable automation id. Physical
locations are repository-relative and use `%SRCROOT%`. Archive findings point
to the real archive while the member is represented as a logical location.
Finding fingerprints exclude line number but include rule id, Skill-relative
path, and normalized evidence, so line movement does not create a new alert.

## Baseline, lock, and cache trust

Baseline files store fingerprint counts, content hash, scanner version, and
rule digest. A tool-version or rule-digest mismatch is an error; an incompatible
baseline never suppresses findings. Full findings remain visible, while only
new findings affect a compatible diff gate.

Lockfiles pin report schema, scan status, source identity, coverage, content and
rule hashes, effective policy, semantic settings, verdict, and report digest.
Neither a baseline nor a lockfile is auto-loaded from scanned content. Pass it
explicitly, or let the Action retrieve it from the trusted base commit.

Cache v2 is an optimization keyed by the complete content manifest and the
effective policy, including resolved semantic settings. Cache v1 entries always
miss. Cache directories must remain outside the scanned target and must not be
links; a cache hit cannot turn incomplete coverage into a passing scan.

## Repository checks

The clean fixture workflow is a smoke test, not evidence of real-world
precision. Repository CI also audits the repository itself while excluding
intentional malicious test fixtures, and separately validates the malicious
fixture, invalid Action input, base-commit baseline behavior, and repeated
Action calls in one job. Public precision claims require the frozen,
human-labeled corpus described in
[research-methodology.md](research-methodology.md).

## Badge meaning

The static "scanned by skill-auditor" badge means the repository has integrated
the tool. Link it to the repository's `Skill security` workflow badge to show
whether the current default-branch commit actually passed.
