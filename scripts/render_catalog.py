#!/usr/bin/env python3
"""Backward-compatible catalog renderer."""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

from skill_auditor.render_catalog import *  # noqa: F403,E402
from skill_auditor.render_catalog import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
