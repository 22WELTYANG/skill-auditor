#!/usr/bin/env python3
"""Backward-compatible wrapper for ``skill-auditor``."""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from skill_auditor.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
