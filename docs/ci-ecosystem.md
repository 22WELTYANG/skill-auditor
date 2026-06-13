# CI and trust infrastructure

## GitHub Action

`action.yml` is a same-repository Composite Action. It installs the Python
package from `GITHUB_ACTION_PATH`, scans without executing target content,
writes JSON and SARIF into `RUNNER_TEMP`, uploads both, and applies the scan
exit code last.

Required workflow permissions:

```yaml
permissions:
  contents: read
  security-events: write
  actions: read
```

On pull requests, `config` and explicit `baseline` paths are read with
`git show` from the base commit. `baseline: auto` safely expands a `git archive`
of the base commit and scans the same input path. Links, devices, traversal
paths, oversized archives, and excessive member counts are never extracted.

Repositories without GitHub Code Security can leave `upload-sarif: true`; the
upload step is non-fatal and the scanner gate still runs. Report artifact upload
is also non-fatal.

## SARIF identity

Each Skill produces one SARIF run with a stable automation id. Physical
locations are repository-relative and use `%SRCROOT%`. Archive findings point
to the real archive while the member is represented as a logical location.
Finding fingerprints exclude line number but include rule id, Skill-relative
path, and normalized evidence, so line movement does not create a new alert.

## Baseline and lock trust

Baseline files store only fingerprint counts, content hash, scanner version,
and rule digest. Full findings remain visible, while only new unresolved
findings affect the gate.

Lockfiles additionally pin semantic policy, verdict, and report digest.
Neither baseline nor lockfile is auto-loaded from scanned content. Pass it
explicitly, or let the Action retrieve it from the trusted base commit.

The local cache is an optimization, not a target-controlled suppression
mechanism. Cache directories must be outside the scanned target, cannot be
links, and are keyed by content, rules, config, source root, scanner version,
and semantic policy.

## Badge meaning

The static "scanned by skill-auditor" badge means the repository has integrated
the tool. Link it to the repository's `Skill security` workflow badge to show
whether the current default-branch commit actually passed.
