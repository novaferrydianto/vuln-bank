#!/usr/bin/env python3
import json
from pathlib import Path
from html import escape

REPORT_DIR = Path("security-reports")
BANDIT_JSON = REPORT_DIR / "bandit.json"
OUT_HTML = REPORT_DIR / "bandit-report.html"


def main():
    if not BANDIT_JSON.is_file():
        print(f"[WARN] {BANDIT_JSON} not found, skipping HTML report.")
        return

    data = json.load(BANDIT_JSON.open("r", encoding="utf-8"))
    results = data.get("results", [])

    rows = []
    for r in results:
        rows.append(
            f"<tr>"
            f"<td>{escape(r.get('filename',''))}</td>"
            f"<td>{escape(str(r.get('line_number','')))}</td>"
            f"<td>{escape(r.get('issue_severity',''))}</td>"
            f"<td>{escape(r.get('test_id',''))}</td>"
            f"<td>{escape(r.get('issue_text',''))}</td>"
            f"</tr>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Bandit Security Report</title>
  <style>
    body {{ font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; font-size: 13px; }}
    th {{ background-color: #111827; color: #f9fafb; text-align: left; }}
    tr:nth-child(even) {{ background-color: #f9fafb; }}
    .sev-HIGH {{ background-color: #fee2e2; }}
    .sev-MEDIUM {{ background-color: #fffbeb; }}
  </style>
</head>
<body>
  <h1>Bandit Security Report</h1>
  <p>Total findings: {len(results)}</p>
  <table>
    <thead>
      <tr>
        <th>File</th>
        <th>Line</th>
        <th>Severity</th>
        <th>Rule</th>
        <th>Message</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
</body>
</html>
"""
    OUT_HTML.parent.mkdir(parents=True, exist_ok=True)
    OUT_HTML.write_text(html, encoding="utf-8")
    print(f"[INFO] Bandit HTML report written to {OUT_HTML}")


if __name__ == "__main__":
    main()
