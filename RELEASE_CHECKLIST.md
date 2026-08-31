# v0.9.0 Release Checklist

This checklist is release readiness documentation. Completing a checkbox does
not authorize creating a tag, publishing to PyPI, or creating a GitHub Release.

## Release outcome (2026-08-31)

- [x] `pyproject.toml`, `src/skill_auditor/__init__.py`, and `SKILL.md` declare
  `0.9.0`.
- [x] Annotated tag `v0.9.0` points to release commit
  `cee3670e8be16527f73ec435110355f10e3dcc3f`.
- [x] PyPI latest is `0.9.0`, published through Trusted Publishing.
- [x] GitHub Latest Release is `v0.9.0` with wheel, sdist, payload manifest,
  and `SHA256SUMS` assets.
- [x] `release.yml` verifies the tag/version match, builds wheel and sdist,
  runs tests, uses PyPI Trusted Publishing, then creates the GitHub Release.
- [x] The v0.9.0 changelog and generated release notes are published.
- [x] The v0.9.0 GitHub Release was completed from the workflow's verified
  artifact after the original release job lacked an explicit `--repo`; the
  workflow is corrected on `main` for future releases.

## 1. Release candidate review

- [ ] Confirm the working tree is clean and `main` matches `origin/main`.
- [ ] Review every commit in `v0.8.0..main`, especially security-policy,
  installer, Action, and release-workflow changes.
- [ ] Confirm no secrets, private fixtures, generated corpora, build output, or
  unexpected binaries are tracked.
- [ ] Confirm `README.md` and `README.zh-CN.md` agree on commands, versions,
  supported ecosystems, and release status.
- [ ] Replace temporary reviewed-commit references in integration examples with
  the final v0.9.0 release commit SHA where appropriate.
- [ ] Freeze `CHANGELOG.md` section `0.9.0` with the release date.

## 2. Version and generated assets

- [ ] Verify exactly `0.9.0` in `pyproject.toml`,
  `src/skill_auditor/__init__.py`, and `SKILL.md`.
- [ ] Run `python scripts/render_catalog.py --check`.
- [ ] Run
  `python -m skill_auditor.installer --source . --check-payload-manifest`.
- [ ] If payload files changed, regenerate and review
  `skill-auditor-payload.json`; confirm it is not self-referential and contains
  no tests, build output, or unreviewed files.

## 3. Local validation

- [ ] `python -m compileall src scripts tests`
- [ ] `python scripts/run_tests.py`
- [ ] `python -S scripts/run_tests.py` to exercise the zero-dependency fallback
- [ ] `python -m pytest`
- [ ] `python -m build`
- [ ] `python -m twine check dist/*`
- [ ] Install the wheel into a clean virtual environment and run
  `skill-auditor --version`.
- [ ] Scan `examples/clean-skill` and confirm exit `0` / `SAFE TO INSTALL`.
- [ ] Scan `examples/malicious-skill` and confirm exit `2` /
  `DO NOT INSTALL`.
- [ ] Generate JSON and SARIF, validate that machine stdout is not polluted,
  and inspect the SARIF in a test Code Scanning run.
- [ ] Validate workflow YAML, Action metadata, ShellCheck, and PSScriptAnalyzer.

## 4. Remote CI and publishing controls

- [ ] Require green `Python checks` and `Skill security` runs for the exact
  release commit on Linux, macOS, Windows, and Python 3.9–3.14.
- [ ] Confirm the GitHub `pypi` environment and its reviewers/protection rules.
- [ ] Confirm the PyPI Trusted Publisher still points to this repository,
  `release.yml`, and the `pypi` environment.
- [ ] Confirm GitHub Actions are pinned to reviewed full commit SHAs.
- [ ] Confirm release permissions remain minimal: `id-token: write` only for
  PyPI publication and `contents: write` only for GitHub Release creation.

## 5. Explicit maintainer authorization required

- [ ] Maintainer approves the final commit as the v0.9.0 release commit.
- [ ] Maintainer explicitly authorizes creation and push of tag `v0.9.0`.
- [ ] Understand that pushing `v0.9.0` triggers production PyPI publication and,
  after it succeeds, GitHub Release creation.
- [ ] Create and push the tag only after the preceding checks pass.

## 6. Post-release verification

- [x] PyPI shows `skill-auditor 0.9.0`, Trusted Publishing provenance, wheel,
  and sdist.
- [x] GitHub shows `v0.9.0` as Latest Release with distributions,
  `skill-auditor-payload.json`, and `SHA256SUMS`.
- [x] Install from PyPI in a clean environment and repeat clean/malicious smoke
  tests.
- [ ] Verify badges and README Quick Start resolve to the published release.
- [x] Record the release and updated adoption snapshot in
  `docs/OPEN_SOURCE_ADOPTION.md`.
