"""Compatibility imports for legacy callers."""

from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

from skill_auditor.rules_loader import *  # noqa: F403,E402
from skill_auditor.rules_loader import _cat_index  # noqa: E402,F401
