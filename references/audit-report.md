# Audit report format

Use this format for a human-readable audit. Fill every section, remove empty
severity subsections, and keep quoted target text as short as the evidence
allows.

```markdown
# Skill Audit: <skill name>

**Target:** <path or URL>
**Resolved source:** <normalized source and commit, or local path>
**Content hash:** <manifest hash>
**Scan status:** <COMPLETE | INCOMPLETE>
**Coverage:** <scanned, exempted, and incomplete entry counts>
**Findings:** <critical> CRITICAL · <warning> WARNING · <info> INFO

## Summary

<What the Skill claims to do, the most important observed behavior, and whether
coverage was complete.>

## Findings

### CRITICAL

- **<rule id · category · concise title>**
  - Evidence: `<file>:<line>` — `> <short snippet>`
  - Scanner rationale: <why the rule matched>
  - Assessment: <true positive, false positive, or uncertain; explain why>

### WARNING

<Use the same shape.>

### INFO

<Use the same shape; keep it brief.>

## Semantic review

<Context the deterministic rules cannot settle: purpose mismatch, prompt
injection, concealment, indirection, trigger-gated behavior, or combined intent.
Identify any semantic provider as advisory or dismissive and record the actual
model, base URL, and prompt version.>

## Coverage and trust inputs

<List incomplete entries and trusted external config/baseline/lock inputs. For
each binary exemption, give its relative path and pinned SHA-256. Say explicitly
whether exempted content is excluded from installation.>

## Install decision

**<SAFE TO INSTALL | REVIEW BEFORE INSTALL | DO NOT INSTALL | ERROR — DO NOT INSTALL>**

<One or two sentences. For REVIEW, state exactly what remains to be checked or
changed. For ERROR, state what prevented a complete audit.>
```

Use **ERROR — DO NOT INSTALL** whenever `scan_status` is `INCOMPLETE`, the
report schema is unsupported, or the scanner exits `3`. A scanner finding may
be assessed as benign only with cited context and an explicit reason.
