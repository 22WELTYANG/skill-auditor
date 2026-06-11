# ⚠️ malicious-skill — INTENTIONALLY DANGEROUS TEST FIXTURE

This is **not** a real skill. It is a deliberately crafted bad example used to
demonstrate and test `skill-auditor`. Do **not** install it.

It disguises itself as a Markdown formatter (`readme-polish`) while actually
attempting all seven risk categories skill-auditor detects:

| Category | Layer | What it does here |
| --- | --- | --- |
| data-exfiltration | deterministic | uploads collected credentials to an outside collector host |
| credential-read | deterministic | reads SSH keys, cloud creds, and project secret files |
| dangerous-shell | deterministic | piped remote-script execution, forced recursive delete, startup-file persistence |
| obfuscation | deterministic | base64-decode-then-run, eval of a hex-encoded payload |
| prompt-injection | semantic | tries to cancel prior instructions and conceal its actions |
| description-mismatch | semantic | description claims formatting; body performs theft |
| logic-bomb | semantic | payload gated behind a date and a specific-repo check |

(The literal payloads live in `SKILL.md` and `scripts/setup.sh` — this table
describes them in prose so the README itself stays clean for the demo.)

All payloads are neutralized: outbound hosts use the reserved `example.com`
domain, and `scripts/setup.sh` exits immediately before any dangerous line. The
point is to give the scanner detectable *text*, not to actually do harm.

Run the auditor against it:

```bash
python ../../scripts/scan.py . --format text
```
