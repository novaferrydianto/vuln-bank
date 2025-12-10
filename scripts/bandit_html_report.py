# scripts/bandit_html_report.py
#!/usr/bin/env python3
import json
import datetime
from pathlib import Path

# Config matches your YAML env vars
REPORT_DIR = Path("security-reports")
INPUT_FILE = REPORT_DIR / "bandit.json"
OUTPUT_FILE = REPORT_DIR / "bandit-report.html"

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Bandit SAST Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; margin: 2rem; color: #333; }}
        h1 {{ border-bottom: 2px solid #eaecef; padding-bottom: 0.3em; }}
        .meta {{ color: #586069; margin-bottom: 20px; font-size: 0.9em; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #e1e4e8; }}
        th {{ background-color: #f6f8fa; font-weight: 600; }}
        tr:hover {{ background-color: #f1f8ff; }}
        .high {{ color: #cb2431; font-weight: bold; }}
        .medium {{ color: #b08800; font-weight: bold; }}
        .low {{ color: #0366d6; }}
        code {{ background: rgba(27,31,35,0.05); padding: 2px 4px; border-radius: 3px; font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; font-size: 85%; }}
        .badge {{ display: inline-block; padding: 2px 6px; border-radius: 20px; color: #fff; font-size: 0.75em; font-weight: 600; }}
        .bg-high {{ background-color: #d73a49; }}
        .bg-medium {{ background-color: #d4a72c; }}
        .bg-low {{ background-color: #0366d6; }}
    </style>
</head>
<body>
    <h1>🛡️ Bandit Security Report</h1>
    <div class="meta">
        Generated: {date} | Source: Vuln Bank CI
    </div>
    
    <table>
        <thead>
            <tr>
                <th style="width: 100px;">Severity</th>
                <th>Issue Details</th>
                <th>Location</th>
                <th style="width: 100px;">Confidence</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</body>
</html>
"""

ROW_TEMPLATE = """
<tr>
    <td><span class="badge bg-{sev_lower}">{severity}</span></td>
    <td>
        <div><strong>{test_id}</strong></div>
        <div style="margin-top:4px;">{text}</div>
    </td>
    <td><code>{filename}:{line}</code></td>
    <td>{confidence}</td>
</tr>
"""

def main():
    if not INPUT_FILE.exists():
        print(f"[WARN] Input file not found: {INPUT_FILE}")
        # Create a dummy file so the artifact upload doesn't fail if Bandit didn't run
        OUTPUT_FILE.write_text("<h3>No Bandit results found.</h3>", encoding="utf-8")
        return

    try:
        data = json.loads(INPUT_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print("[ERROR] Could not decode Bandit JSON")
        return

    results = data.get("results", [])
    
    # Sort: High -> Medium -> Low
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    results.sort(key=lambda x: severity_order.get(x.get("issue_severity"), 99))

    rows = []
    for r in results:
        severity = r.get("issue_severity", "LOW")
        rows.append(ROW_TEMPLATE.format(
            sev_lower=severity.lower(),
            severity=severity,
            test_id=r.get("test_id", "N/A"),
            text=r.get("issue_text", "No description"),
            filename=r.get("filename", ""),
            line=r.get("line_number", ""),
            confidence=r.get("issue_confidence", "N/A")
        ))

    html = HTML_TEMPLATE.format(
        date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        rows="".join(rows) if rows else "<tr><td colspan='4'><i>No issues found. Great job!</i></td></tr>"
    )

    OUTPUT_FILE.write_text(html, encoding="utf-8")
    print(f"[INFO] Generated Bandit HTML report at: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()