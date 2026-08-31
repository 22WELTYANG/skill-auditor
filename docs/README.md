# Documentation

- [CI and trust infrastructure](ci-ecosystem.md) ·
  [简体中文](ci-ecosystem.zh-CN.md)
- [Public Skill corpus methodology](research-methodology.md)
- [Public research report template](research-report-template.md)
- [Open-source adoption evidence](OPEN_SOURCE_ADOPTION.md)
- Demo recording instructions below

## Regenerating `demo.gif`

The README's Demo section embeds `docs/demo.gif`: a short recording of the
scanner auditing `examples/malicious-skill` (→ **DO NOT INSTALL**) and then
`examples/clean-skill` (→ **SAFE TO INSTALL**).

The script verifies the expected exit codes (`2` for the intentionally
malicious fixture and `0` for the clean fixture) before rendering the GIF, so a
changed scanner result cannot silently produce a misleading demo.

With [asciinema](https://asciinema.org) and
[agg](https://github.com/asciinema/agg) installed (Linux, macOS, or WSL):

```bash
bash docs/record-demo.sh
```

Keep the GIF under ~1.5 MB so clones stay light.

On Windows without WSL, a screen recorder such as
[ScreenToGif](https://www.screentogif.com/) pointed at Windows Terminal works
as a fallback — record the same two commands the script runs.

Once the GIF exists, enable the commented-out `<img>` block at the top of the
Demo section in both `README.md` and `README.zh-CN.md`.
