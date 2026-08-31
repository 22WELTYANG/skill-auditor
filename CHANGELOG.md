# Changelog

All notable changes are recorded here. This project follows Semantic
Versioning; `0.x` releases may still refine interfaces, with deprecations
documented before removal.

## [0.9.0] - 2026-08-31

### Security and trust

- Add fail-closed report coverage, immutable source identity, manifest-backed
  scans, and transactional installation from reviewed bytes.
- Harden archive, filesystem-boundary, baseline, cache, lockfile, and GitHub
  Action trust boundaries.
- Preserve SARIF output and upload reports before applying the CI exit-code
  gate.

### Compatibility and packaging

- Support Python 3.9 through 3.14 on Linux, macOS, and Windows.
- Preserve the zero-required-dependency runtime and built-in YAML fallback.
- Validate wheel, sdist, payload manifest, CLI entry points, and PyPI Trusted
  Publishing in the release workflow.

### Documentation and adoption

- Clarify positioning for Codex, Claude Code, Cursor, prompt injection, and AI
  supply-chain security.
- Add reproducible demo, CLI, GitHub Action, pre-commit, SARIF, and CI-gating
  examples.
- Add community health files, adoption evidence tracking, and a release
  checklist.

## [0.8.0] - 2026-06-13

- Published the current stable PyPI package and GitHub Action release.

[0.9.0]: https://github.com/22WELTYANG/skill-auditor/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/22WELTYANG/skill-auditor/releases/tag/v0.8.0
