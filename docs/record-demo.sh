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

for command in asciinema agg python; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "missing required command: $command" >&2
    exit 1
  fi
done

rm -f "$CAST"
# The command is intentionally single-quoted: its variables belong to the
# shell spawned by asciinema, not to this recording wrapper.
# shellcheck disable=SC2016
asciinema rec "$CAST" --cols 100 --rows 32 --idle-time-limit 2 --command '
  set -eu
  echo "\$ python scripts/scan.py examples/malicious-skill --format text"
  sleep 1
  malicious_exit=0
  python scripts/scan.py examples/malicious-skill --format text || malicious_exit=$?
  echo "expected gate exit: $malicious_exit"
  test "$malicious_exit" -eq 2
  sleep 3
  echo
  echo "\$ python scripts/scan.py examples/clean-skill --format text"
  sleep 1
  python scripts/scan.py examples/clean-skill --format text
  echo "expected gate exit: 0"
  sleep 3
'
agg --font-size 14 "$CAST" "$GIF"
rm -f "$CAST"
echo "wrote $GIF ($(du -h "$GIF" | cut -f1)) — keep it under ~1.5 MB"
