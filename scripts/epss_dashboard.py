#!/usr/bin/env python3
"""
Generate EPSS + CISA KEV Dashboard as static HTML output.

Creates:
  site/index.html

Input:
  security-reports/epss-findings.json
"""

import json
import os
from pathlib import Path
import pandas as pd
import plotly.express as px
from jinja2 import Template

INPUT_FILE = "security-reports/epss-findings.json"
OUTPUT_DIR = Path("site")
OUTPUT_FILE = OUTPUT_DIR / "index.html"


# -------------------------------------------------------------------
# Ensure directories exist
# -------------------------------------------------------------------
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# -------------------------------------------------------------------
# Load EPSS findings
# -------------------------------------------------------------------
if not os.path.exists(INPUT_FILE):
    raise FileNotFoundError(
        f"EPSS findings not found: {INPUT_FILE}\n"
        "Make sure epss_gate.py has already run."
    )

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    data = json.load(f)

threshold = data.get("threshold", 0.5)
vulns = data.get("high_risk", [])
total = data.get("total_high_crit_from_trivy", 0)


# -------------------------------------------------------------------
# Convert vulns → DataFrame
# -------------------------------------------------------------------
if vulns:
    df = pd.DataFrame(vulns)
else:
    df = pd.DataFrame(columns=["cve", "severity", "epss", "is_kev"])


# -------------------------------------------------------------------
# Create EPSS Chart
# -------------------------------------------------------------------
if not df.empty:
    fig = px.bar(
        df.sort_values("epss", ascending=False),
        x="cve",
        y="epss",
        color="is_kev",
        title="EPSS Scores (Higher = Higher Exploit Probability)",
        labels={"epss": "EPSS Score", "cve": "CVE"},
        color_discrete_map={True: "red", False: "blue"},
    )
    epss_chart_html = fig.to_html(include_plotlyjs="cdn", full_html=False)
else:
    epss_chart_html = "<p>No high-risk vulnerabilities found.</p>"


# -------------------------------------------------------------------
# Build Risk Table HTML
# -------------------------------------------------------------------
if not df.empty:
    risk_table_html = df.to_html(
        justify="center",
        classes="table table-striped",
        index=False,
        escape=False,
    )
else:
    risk_table_html = "<p>No vulnerabilities met EPSS/KEV criteria.</p>"


# -------------------------------------------------------------------
# Jinja2 HTML Template
# -------------------------------------------------------------------
html_template = Template("""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>EPSS / CISA KEV Dashboard – Vuln Bank</title>
    <link rel="stylesheet"
          href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
</head>
<body class="bg-light">

<div class="container py-4">

    <h1 class="mb-3">EPSS / CISA KEV Dashboard</h1>

    <p class="text-muted">
        Threshold: <strong>{{ threshold }}</strong><br>
        Total HIGH/CRITICAL from Trivy: <strong>{{ total }}</strong><br>
        High-risk findings: <strong>{{ count }}</strong>
    </p>

    <hr>

    <h3>EPSS Score Distribution</h3>
    <div class="border rounded p-3 bg-white">
        {{ epss_chart | safe }}
    </div>

    <hr>

    <h3>High-Risk Vulnerabilities Table</h3>
    <div class="border rounded p-3 bg-white">
        {{ risk_table | safe }}
    </div>

</div>

</body>
</html>
""")

# -------------------------------------------------------------------
# Render HTML
# -------------------------------------------------------------------
html_output = html_template.render(
    threshold=threshold,
    total=total,
    count=len(vulns),
    epss_chart=epss_chart_html,
    risk_table=risk_table_html,
)

OUTPUT_FILE.write_text(html_output, encoding="utf-8")

print(f"[INFO] Dashboard generated: {OUTPUT_FILE}")
