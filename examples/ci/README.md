# Generic CI: fail on CRITICAL

Most CI systems only need the CLI exit-code contract:

```bash
python -m pip install skill-auditor
skill-auditor scan . --recursive --fail-on critical --format text
```

The job fails with exit `2` when a CRITICAL finding meets the gate and with exit
`3` when coverage is incomplete or the scan errors. Do not convert exit `3` to a
pass.

To retain a machine report and still preserve the gate:

```bash
skill-auditor scan . --recursive --fail-on critical \
  --format json --output skill-auditor.json
```

For GitHub Code Scanning, use the [Composite Action example](../github-actions/),
which uploads SARIF before applying the same gate.
