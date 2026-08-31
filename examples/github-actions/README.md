# GitHub Actions example

Copy [`skill-auditor.yml`](skill-auditor.yml) to
`.github/workflows/skill-auditor.yml`. It uses the repository's current
Composite Action inputs, uploads JSON and SARIF, and applies `fail-on: critical`
after uploads.

The example pins exact commits. The Skill Auditor pin is the latest verified
v0.9.0 preparation commit, not a release tag. Replace it with the final reviewed
release commit after v0.9.0 is published.

Repositories without GitHub Code Security can set `upload-sarif: "false"` while
keeping JSON artifact upload and the exit-code gate.
