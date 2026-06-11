#!/usr/bin/env bash
#
# skill-auditor installer.
#
#   Remote (one-liner):
#     curl -fsSL https://raw.githubusercontent.com/your-org/skill-auditor/main/install.sh | bash
#
#   Local (from a clone):
#     ./install.sh
#
# Install targets (verified June 2026):
#   ~/.claude/skills   Claude Code global skills dir.                  [primary]
#   ~/.codex/skills    Codex global skills dir (openai/skills uses it).[primary]
#   ~/.agents/skills   Emerging cross-agent neutral location.          [forward-looking]
#   ~/.cursor/skills   Cursor's own global dir (newer versions only).  [fallback]
# Note: recent Cursor auto-loads skills from ~/.claude/skills and ~/.codex/skills,
# so installing to the two primaries already covers Cursor on current versions.
# Older Cursor only supports project-level .cursor/skills; the ~/.cursor copy is
# a best-effort fallback for those.
#
# Override every target with:  SKILLS_DIR=/path ./install.sh
#
set -euo pipefail

REPO_URL="${SKILL_AUDITOR_REPO:-https://github.com/your-org/skill-auditor}"
SKILL_NAME="skill-auditor"

say()  { printf '  %s\n' "$*"; }
ok()   { printf '  \033[1;32m✓\033[0m %s\n' "$*"; }
note() { printf '  \033[1;36mi\033[0m %s\n' "$*"; }
warn() { printf '  \033[1;33m!\033[0m %s\n' "$*"; }

# --- locate the source tree (local clone, or fetch a temp clone) ------------ #
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
CLEANUP=""
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/SKILL.md" ]; then
  SRC="$SCRIPT_DIR"
  say "Installing from local checkout: $SRC"
else
  command -v git >/dev/null 2>&1 || { echo "error: git is required for remote install" >&2; exit 1; }
  SRC="$(mktemp -d)"
  CLEANUP="$SRC"
  say "Cloning $REPO_URL ..."
  git clone --depth 1 "$REPO_URL" "$SRC" >/dev/null 2>&1
fi
trap '[ -n "$CLEANUP" ] && rm -rf "$CLEANUP"' EXIT

# --- copy the skill into one target dir ------------------------------------- #
install_to() {
  local dest="$1/$SKILL_NAME"
  mkdir -p "$dest"
  cp "$SRC/SKILL.md" "$dest/"
  cp -R "$SRC/scripts" "$dest/"
  cp -R "$SRC/rules" "$dest/"
  cp -R "$SRC/references" "$dest/"
  ok "Installed to $dest"
}

# --- decide where to install ------------------------------------------------ #
if [ -n "${SKILLS_DIR:-}" ]; then
  install_to "$SKILLS_DIR"
else
  # primary targets (always installed)
  install_to "$HOME/.claude/skills"
  install_to "$HOME/.codex/skills"
  # forward-looking neutral location
  install_to "$HOME/.agents/skills"
  # Cursor fallback: only if the user actually has Cursor
  if [ -d "$HOME/.cursor" ]; then
    install_to "$HOME/.cursor/skills"
    note "Cursor: newer versions auto-load from ~/.claude/skills; this ~/.cursor copy is only a fallback for older versions."
  fi
fi

command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1 \
  || warn "Python 3 not found on PATH — scan.py needs it at scan time."

echo
ok "Done. Try it:"
say "  ask your agent:  \"audit this skill before I install it: <path-or-url>\""
say "  or directly:     python ~/.claude/skills/$SKILL_NAME/scripts/scan.py <path-or-url> --format text"
