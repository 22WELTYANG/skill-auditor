#!/usr/bin/env bash
# Run this only from a reviewed, fixed release or commit checkout.
set -euo pipefail

if ! SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd -P)"; then
  SCRIPT_DIR=""
fi
if [ -z "$SCRIPT_DIR" ] || [ ! -f "$SCRIPT_DIR/SKILL.md" ]; then
  printf '%s\n' 'install error: run this from a reviewed fixed checkout' >&2
  exit 3
fi

PYTHON_BIN="$(command -v python3 || command -v python || true)"
if [ -z "$PYTHON_BIN" ]; then
  printf '%s\n' 'install error: Python 3.9 or newer is required' >&2
  exit 3
fi

INSTALL_ARGS=(--source "$SCRIPT_DIR")
if [ -n "${SKILLS_DIR:-}" ]; then
  INSTALL_ARGS+=(--skills-dir "$SKILLS_DIR")
fi

if PYTHONPATH="$SCRIPT_DIR/src${PYTHONPATH:+:$PYTHONPATH}" \
  "$PYTHON_BIN" -m skill_auditor.installer "${INSTALL_ARGS[@]}"; then
  exit 0
else
  exit 3
fi
