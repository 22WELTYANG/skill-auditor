# CLI examples

Install the latest published package and scan one Skill directory:

```bash
python -m pip install skill-auditor
skill-auditor scan ./my-skill --format text
```

Scan every discovered Skill below a parent directory and fail the process when
a CRITICAL finding is present:

```bash
skill-auditor scan ./skills --recursive --fail-on critical --format text
```

Write machine-readable reports without mixing operational messages into stdout:

```bash
skill-auditor scan ./my-skill --format json --output audit.json
skill-auditor scan ./my-skill --format sarif --output audit.sarif
```

Verdict and gate contract:

| Exit | Meaning |
| ---: | --- |
| `0` | Configured gate passed; still inspect findings below the gate threshold |
| `1` | A non-critical finding met the gate |
| `2` | A critical finding met the gate — do not install |
| `3` | Scan error or incomplete coverage — fail closed |

The default text report prints CRITICAL, WARNING, and INFO counts plus one of
`SAFE TO INSTALL`, `REVIEW BEFORE INSTALL`, `DO NOT INSTALL`, or `ERROR`.
