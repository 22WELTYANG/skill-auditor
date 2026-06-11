# docs/

Demo assets for the main README live here.

## Regenerating `demo.gif`

The README's Demo section embeds `docs/demo.gif`: a short recording of the
scanner auditing `examples/malicious-skill` (→ **DO NOT INSTALL**) and then
`examples/clean-skill` (→ **SAFE TO INSTALL**).

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
