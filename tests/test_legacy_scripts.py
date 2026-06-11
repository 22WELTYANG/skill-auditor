from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def test_legacy_scripts_prioritize_source_package():
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    commands = [
        [sys.executable, "scripts/render_catalog.py", "--check"],
        [sys.executable, "scripts/scan.py", "--version"],
        [sys.executable, "scripts/skill_auditor.py", "--version"],
        [sys.executable, "scripts/run_tests.py"],
    ]
    for command in commands:
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        assert result.returncode == 0, (
            f"{command[1]} failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
