# Integration examples

These examples use only interfaces implemented by the current repository.

- [CLI](cli/README.md) — scan one Skill, a directory of Skills, and emit reports.
- [GitHub Actions](github-actions/) — CI gate plus SARIF Code Scanning upload.
- [pre-commit](pre-commit/) — scan repository Skills before a commit.
- [Generic CI fail-on-critical](ci/README.md) — portable command and exit-code
  contract for other CI systems.
- `clean-skill/` and `malicious-skill/` are regression/demo fixtures, not
  installable recommendations.

Integration files pin reviewed v0.9.0 commit
`02cfa26f990a5102f60519b32ee200e13a4d4ae8` so copied workflows do not depend
on a mutable branch or tag.
