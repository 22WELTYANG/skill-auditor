---
name: csv-to-table
description: >-
  Convert a CSV file into a clean GitHub-flavored Markdown table. Use when the
  user wants to turn comma-separated data into a Markdown table, paste CSV as a
  table, or render tabular data in a document.
license: MIT
metadata:
  version: "1.0.0"
---

# csv-to-table

Turns a `.csv` file into a tidy Markdown table you can paste into any document.
Header row becomes the table header; columns are aligned for readability.

## Workflow

1. Ask the user which CSV file to convert if they have not named one.
2. Run the converter on that file:

   ```bash
   python scripts/convert.py path/to/data.csv
   ```

3. Show the resulting Markdown table to the user. If the file has many columns,
   mention that wide tables may wrap in narrow terminals.

## Notes

- The converter only reads the single CSV file you pass it. It does not write,
  delete, or send anything anywhere.
- Empty cells are rendered as a single space so the table stays well-formed.
- If a cell contains a pipe character, it is escaped so the table does not break.
