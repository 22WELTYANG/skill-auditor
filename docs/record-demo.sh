#!/usr/bin/env bash
#
# Regenerate docs/demo.gif — the recording embedded at the top of the README.
#
# Requirements: asciinema (https://asciinema.org) and agg
# (https://github.com/asciinema/agg) on Linux, macOS, or WSL.
#
#   bash docs/record-demo.sh
#
set -euo pipefail
cd "$(dirname "$0")/.."

CAST="docs/demo.cast"
GIF="docs/demo.gif"

rm -f "$CAST"
asciinema rec "$CAST" --cols 100 --rows 32 --idle-time-limit 2 --command '
  echo "\$ python scripts/scan.py examples/malicious-skill --format text"
  sleep 1
  python scripts/scan.py examples/malicious-skill --format text
  sleep 3
  echo
  echo "\$ python scripts/scan.py examples/clean-skill --format text"
  sleep 1
  python scripts/scan.py examples/clean-skill --format text
  sleep 3
'
agg --font-size 14 "$CAST" "$GIF"
rm -f "$CAST"
echo "wrote $GIF ($(du -h "$GIF" | cut -f1)) — keep it under ~1.5 MB"
