# Support

## Usage questions

First check the [README](README.md), the [integration examples](examples/), and
the [CI trust model](docs/ci-ecosystem.md). If the documented behavior does not
answer the question, open an issue using the closest template and include:

- `skill-auditor --version`;
- operating system and Python version;
- the exact command and exit code;
- a minimal, redacted fixture or report; and
- whether the scan was local, recursive, archive-based, or remote.

Do not attach credentials, private source, active malicious URLs, or an
unredacted report from a private repository.

## Detection feedback

Use the dedicated templates for false positives, missed detections, new rule
proposals, or suspicious Skills. A safe minimal reproducer plus the expected
severity is more useful than a screenshot alone.

## Security vulnerabilities

Do not open a public issue for a vulnerability in Skill Auditor itself. Follow
[SECURITY.md](SECURITY.md) and use GitHub private vulnerability reporting.

Support is provided on a best-effort basis. No response-time or compatibility
commitment is implied beyond the supported versions documented in the security
policy and package metadata.
