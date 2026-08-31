## Summary

<!-- What changed, and what user or security problem does it solve? -->

## Evidence

<!-- Link the issue or threat pattern. Include safe, minimal before/after evidence. -->

## Validation

- [ ] `python scripts/run_tests.py`
- [ ] `python -m pytest`
- [ ] `python scripts/render_catalog.py --check` (when rules or catalog may change)
- [ ] Clean and malicious fixture smoke tests (when scanner behavior may change)
- [ ] Documentation and integration examples match the real CLI/Action interface

## Safety and compatibility

- [ ] I did not execute untrusted target Skill content during review.
- [ ] I did not remove a rule or weaken fail-closed behavior without explicit rationale.
- [ ] Python 3.9–3.14, zero-dependency fallback, SARIF, and cross-platform behavior remain supported.
- [ ] I did not create a tag, publish a package, or trigger a production release.

## Generated files

<!-- If rules changed, confirm rules/*.yaml was the source and generated mirrors were regenerated. -->
