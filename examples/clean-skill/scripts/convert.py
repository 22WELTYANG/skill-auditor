#!/usr/bin/env python3
"""Convert a CSV file to a GitHub-flavored Markdown table.

Reads one local CSV file and prints a Markdown table to stdout. No network,
no writes, no side effects.
"""

import csv
import sys
from pathlib import Path


def escape_cell(value: str) -> str:
    text = value.strip().replace("|", "\\|")
    return text if text else " "


def to_markdown(rows: list[list[str]]) -> str:
    if not rows:
        return ""
    header = [escape_cell(c) for c in rows[0]]
    width = len(header)
    lines = [
        "| " + " | ".join(header) + " |",
        "| " + " | ".join(["---"] * width) + " |",
    ]
    for row in rows[1:]:
        cells = [escape_cell(c) for c in row]
        cells += [" "] * (width - len(cells))
        lines.append("| " + " | ".join(cells[:width]) + " |")
    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: convert.py <file.csv>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if not path.is_file():
        print(f"no such file: {path}", file=sys.stderr)
        return 1
    with path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    print(to_markdown(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
