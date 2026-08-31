# Open-Source Adoption Evidence

This document maintains verifiable adoption evidence for project planning and a
future OpenAI Codex for Open Source application. It is intentionally
conservative: private usage, self-integration, bots, and unverified mentions do
not count as external adoption.

## Evidence snapshot

Last checked: **2026-08-31**. GitHub values were read from the public repository
API and public code search. PyPI release state was checked on PyPI. PyPIStats
returned an upstream rate-limit response, so monthly downloads are deliberately
not recorded in this snapshot.

| Signal | Verified value | Evidence / counting rule |
| --- | ---: | --- |
| GitHub Stars | 2 | [Stargazers](https://github.com/22WELTYANG/skill-auditor/stargazers) |
| Forks | 0 | [Fork network](https://github.com/22WELTYANG/skill-auditor/forks) |
| PyPI monthly downloads | Not recorded | Refresh from the PyPIStats `recent` API; do not estimate from badges |
| External human contributors | 0 | Repository contributors list contained only the maintainer |
| External public Issues | 0 | No public Issues existed at snapshot time |
| External human Pull Requests | 0 | Maintainer and Dependabot PRs are excluded |
| Verified external Action integrations | 0 | Exact public code search returned no external repository matches |
| Public releases | 3 | `v0.4.0`, `v0.8.0`, and `v0.9.0` |

These are dated facts, not targets and not live counters. Refresh the snapshot
before using it in an application.

## 1. Project Summary

Skill Auditor is a read-only, fail-closed security scanner and installation gate
for third-party AI Agent Skills. It scans Skill instructions and bundled code
for prompt injection, credential access, data exfiltration, dangerous execution,
persistence, tampering, and supply-chain risks without importing or executing
the target.

## 2. Why this project matters

An Agent Skill can combine trusted-context instructions with shell, Python,
JavaScript, installers, hooks, and configuration changes. That makes a Skill
both an untrusted prompt and untrusted code. Skill Auditor adds a reproducible
review step before installation and a machine-enforceable gate for repositories.

## 3. AI/Codex ecosystem relevance

- Native `SKILL.md` review workflow for OpenAI Codex Skills.
- Compatible review surface for Claude Code and Cursor Skills using the same
  frontmatter-based layout.
- Local CLI, pre-commit, GitHub Action, JSON, Markdown, and SARIF integration.
- Optional semantic review is advisory by default; deterministic evidence and
  fail-closed coverage remain authoritative.

## 4. GitHub Stars

Record the dated value, repository URL, and collection method. Prefer the GitHub
API or repository UI over screenshots. Current snapshot: **2**.

## 5. Forks

Record only the public GitHub fork count. Current snapshot: **0**. Do not infer
usage from a fork without evidence that it integrates or distributes the tool.

## 6. PyPI monthly downloads

Use the PyPIStats last-month value, which excludes known mirrors, and record the
retrieval date. The current value is **not recorded** because the upstream API
was rate-limited during this audit. A live badge may be shown in the README, but
an application should use a dated API snapshot.

```bash
curl https://pypistats.org/api/packages/skill-auditor/recent
```

## 7. External contributors

Count human contributors other than the maintainer. Exclude bots and commits
authored by the maintainer through another local identity unless verified.
Current verified count: **0**.

## 8. External Issues

Count Issues opened by external humans and link representative bug reports,
false positives, missed detections, and integration requests. Current verified
count: **0**.

## 9. External Pull Requests

Count merged and open Pull Requests authored by external humans. Keep bots in a
separate maintenance metric. Current verified count: **0**.

## 10. Public projects using Skill Auditor

Maintain a table only after a project owner, public workflow, dependency file,
or documentation link verifies usage.

| Project | Evidence | Integration type | First verified | Last rechecked |
| --- | --- | --- | --- | --- |
| _No external project verified yet_ | — | — | — | 2026-08-31 |

## 11. GitHub Action integrations

Search public indexed code for the exact Action owner/repository and inspect each
match. Exclude this repository's self-test workflow. Current verified external
integrations: **0**.

```bash
gh search code 'uses: 22WELTYANG/skill-auditor' --limit 100
```

## 12. Release activity

Public releases verified at snapshot time:

- `v0.4.0` — 2026-06-11
- `v0.8.0` — 2026-06-13
- `v0.9.0` — 2026-08-31, current GitHub and PyPI release

The v0.9.0 release includes wheel and sdist distributions, a payload manifest,
and published SHA-256 checksums.

## 13. Security impact examples

The bundled malicious fixture demonstrates detection of credential reads, data
exfiltration, remote-script execution, destructive shell commands, obfuscation,
prompt injection, description mismatch, and trigger-gated behavior. The clean
fixture provides a regression control. These are test fixtures, not evidence of
a prevented real-world incident.

For real impact evidence, record a redacted report, affected rule IDs, project
owner confirmation, fix link, and disclosure status. Never publish private
target content or active secrets.

## 14. Community mentions

Record only attributable public references such as talks, posts, newsletters,
package lists, or maintainer testimonials. Include the URL, author, date, and a
short neutral description. Current verified external mentions: **0**.

## 15. Future milestones

- Publish v0.9.0 only after the release checklist and explicit maintainer
  approval.
- Obtain the first verified external integration through copyable Action and
  pre-commit examples.
- Collect real false-positive and missed-detection reports through structured
  Issue forms.
- Publish corpus precision/recall results only after the documented human-label
  methodology is complete.
- Refresh this evidence snapshot monthly and before any application submission.

## Refresh procedure

Store raw links or command output with the application workpapers; do not commit
private data. At minimum, recheck GitHub repository metadata, contributors,
Issues, PRs, public code references, PyPI latest version, PyPIStats, releases,
and the project list above. Change a value only when its evidence is reproducible.
