"""Compatibility imports for legacy callers."""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

from skill_auditor.formats import *  # noqa: F403,E402
