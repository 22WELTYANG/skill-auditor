# docs/

Place demo assets here. The main `README.md` references `docs/demo.png`.

To capture the screenshot used in the README:

```bash
python scripts/scan.py examples/malicious-skill --format text
```

Screenshot the output (terminal with a UTF-8-capable font) and save it as
`docs/demo.png`. For an animated demo:

```bash
asciinema rec docs/demo.cast \
  -c "python scripts/scan.py examples/malicious-skill --format text"
# then convert to GIF with agg, or embed the asciinema player badge.
```
