# Integration examples

These examples use only interfaces implemented by the current repository.

- [CLI](cli/README.md) — scan one Skill, a directory of Skills, and emit reports.
- [GitHub Actions](github-actions/) — CI gate plus SARIF Code Scanning upload.
- [pre-commit](pre-commit/) — scan repository Skills before a commit.
- [Generic CI fail-on-critical](ci/README.md) — portable command and exit-code
  contract for other CI systems.
- `clean-skill/` and `malicious-skill/` are regression/demo fixtures, not
  installable recommendations.

Until v0.9.0 is released, integration files pin the reviewed v0.9.0 preparation
commit `2d372dfceca674f019cd4e326aa541a4f809b8b3`. Replace it with the final
reviewed v0.9.0 release commit after publication.
