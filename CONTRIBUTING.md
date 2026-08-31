# Contributing to Skill Auditor

Thank you for helping make third-party AI Agent Skills safer to review before
installation. Small, evidence-backed changes are preferred over broad detector
claims or large dependency additions.

## Good first contributions

- Report a false positive with the smallest safe reproducer.
- Report a missed detection without including live credentials or harmful
  infrastructure.
- Add a positive and negative fixture for a real attack pattern.
- Improve an integration example or platform-specific instruction.

Use the matching [issue template](https://github.com/22WELTYANG/skill-auditor/issues/new/choose)
before proposing a large behavior or interface change.

## Development setup

Python 3.9 or newer is supported. The runtime has no required third-party
dependencies; the test extra installs development tools.

```bash
python -m venv .venv
python -m pip install -e ".[test]"
python scripts/run_tests.py
python -m pytest
```

On Windows, activate with `.\.venv\Scripts\Activate.ps1`. On Linux and macOS,
use `source .venv/bin/activate`.

## Adding or changing a security rule

1. Edit the source rule in `rules/*.yaml`. Do not edit
   `src/skill_auditor/rules/` or `references/risk-patterns.md` by hand.
2. Add focused positive and negative fixtures in `tests/cases.py` or
   `tests/fixtures/rules/`.
3. Run `python scripts/render_catalog.py` to regenerate the packaged mirror and
   rule catalog.
4. Run `python scripts/render_catalog.py --check`, the zero-dependency suite,
   and pytest.
5. Explain the threat, expected severity, false-positive boundary, and safe
   test evidence in the pull request.

Rules should cite observable behavior. A detector that matches a risky keyword
without distinguishing common benign use needs stronger context or semantic
review guidance.

## Pull request checks

Before opening a pull request, run what applies:

```bash
python scripts/render_catalog.py --check
python -m skill_auditor.installer --source . --check-payload-manifest
python scripts/run_tests.py
python -m pytest
python -m build
python -m twine check dist/*
```

Also smoke-test `skill-auditor --version`, a clean fixture, and the intentionally
malicious fixture. Do not execute target Skill content during review.

Do not change the package version, create a tag, or publish a release in an
ordinary contribution. Release actions remain maintainer-controlled.

By participating, you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). For
private vulnerability reports, follow [SECURITY.md](SECURITY.md).
