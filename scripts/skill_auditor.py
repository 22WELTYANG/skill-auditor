#!/usr/bin/env python3
"""
skill_auditor.py — the `skill-auditor` command.

Thin entry point so the tool reads naturally:

    python scripts/skill_auditor.py scan    <dir|url>
    python scripts/skill_auditor.py scan --all
    python scripts/skill_auditor.py install <dir|url>

All logic lives in scan.py; this just forwards argv so both `scan.py` (kept for
back-compat) and `skill_auditor.py` share one implementation.
"""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import scan  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(scan.main())
