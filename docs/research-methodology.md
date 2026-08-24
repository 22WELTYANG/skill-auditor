# Public Skill corpus methodology

This document defines the planned reproducible method; it is not a published
precision result. Do not claim corpus prevalence, per-rule precision, or
reviewer agreement until a frozen snapshot and completed labels are released.

The scheduled research workflow discovers at least 500 public repositories,
pins their default-branch commit SHA and license metadata, and downloads
read-only GitHub tarballs. It never executes repository hooks, installers, or
Skill instructions.

Tarballs are expanded into temporary storage with traversal, link, device,
member-count, and expanded-size guards. Source is deleted after each scan.
Published artifacts contain repository name, commit, Skill path, rule,
severity, category, fingerprint, artifact location, and line number only.
Snippets, file bodies, and credential values are not retained.

The labeling command builds a deterministic rule-stratified sample of up to
1,000 unique fingerprints and marks 20 percent for independent second review.
Labels are `true_positive`, `false_positive`, or `uncertain`. Statistics report
per-rule precision with a 95 percent Wilson interval and preserve the uncertain
count separately.

Research releases must freeze:

- repository and commit manifest;
- scanner version and rule digest;
- aggregate repository, Skill, category, and rule counts;
- labeling instructions and reviewer-agreement result;
- licensing limitations and the statement that a dangerous pattern is not
  proof of malicious intent.

Confirmed false positives are reduced to synthetic negative fixtures. Third
party source is never copied into this repository.
