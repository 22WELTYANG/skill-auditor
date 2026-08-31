# pre-commit example

Copy [`.pre-commit-config.yaml`](.pre-commit-config.yaml) into the consuming
repository, then run:

```bash
python -m pip install pre-commit
pre-commit install
pre-commit run skill-auditor --all-files
```

The shipped hook scans all repository Skill roots recursively and fails on
CRITICAL findings. It intentionally ignores the filenames passed by pre-commit
because a Skill's behavior can span instructions and multiple scripts.
