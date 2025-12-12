#!/usr/bin/env python3
"""
EPSS / CISA KEV Security Dashboard Generator
===========================================

Inputs:
  --input   security-reports/epss-findings.json
  --outdir  site/

Outputs:
  site/
    index.html        (Overview / KPI)
    risks.html        (Per-CVE table)
    packages.html     (Grouped by package)
    history.html      (Trend over time)

Design goals:
- Zero crashes on empty data
- CI-safe
- GitHub Pages friendly
- Executive-ready UI
"""

import argparse
import json
from pathlib import Path
from datetime import datetime

import pandas as pd
import plotly.express as px
from jinja2 import Environment, FileSystemLoader

# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--outdir", required=True)
    return p.parse_args()

# ---------------------------------------------------------------------
# Priority model (risk-based)
# ---------------------------------------------------------------------
def compute_priority(row):
    epss = float(row.get("epss", 0)) * 100 * 0.5
    cvss = float(row.get("cvss") or 0) * 10 * 0.3
    kev  = 20 if row.get("is_kev") else 0
    sev  = 10 if row.get("severity") == "CRITICAL" else 0
    return round(epss + cvss + kev + sev, 2)

# ---------------------------------------------------------------------
# Data loaders
# ---------------------------------------------------------------------
def load_findings(path):
    with open(path) as f:
        data = json.load(f)

    rows = data.get("high_risk", [])
    if not rows:
        return pd.DataFrame(), data.get("threshold", "N/A")

    df = pd.DataFrame(rows)
    df["priority_score"] = df.apply(compute_priority, axis=1)
    df = df.sort_values("priority_score", ascending=False)
    return df, data.get("threshold", "N/A")

def load_history():
    hist = Path("security-reports/epss-history.jsonl")
    if not hist.exists():
        return pd.DataFrame()

    return pd.read_json(hist, lines=True)

# ---------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------
def render_template(template, out, **ctx):
    env = Environment(loader=FileSystemLoader("templates"))
    tpl = env.get_template(template)
    Path(out).write_text(tpl.render(**ctx), encoding="utf-8")

# ---------------------------------------------------------------------
# EMPTY STATE (Clean Scan)
# ---------------------------------------------------------------------
def render_clean_dashboard(outdir, threshold):
    html = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>EPSS / KEV Dashboard</title>
  <style>
    body {{
      background: #0b1220;
      color: #e5e7eb;
      font-family: system-ui, -apple-system, BlinkMacSystemFont;
      padding: 50px;
    }}
    .card {{
      max-width: 900px;
      margin: auto;
      background: linear-gradient(135deg, #16a34a, #22c55e);
      border-radius: 18px;
      padding: 48px;
      box-shadow: 0 30px 60px rgba(0,0,0,.45);
    }}
    h1 {{
      font-size: 44px;
      margin: 0;
    }}
    p {{
      font-size: 18px;
      margin-top: 14px;
    }}
    .meta {{
      margin-top: 20px;
      opacity: .9;
      font-size: 14px;
    }}
    .footer {{
      margin-top: 40px;
      text-align: center;
      opacity: .6;
      font-size: 13px;
    }}
  </style>
</head>
<body>
  <div class="card">
    <h1>✅ 0 High-Risk Vulnerabilities</h1>
    <p>EPSS and CISA KEV prioritization passed successfully.</p>
    <div class="meta">
      EPSS Threshold: <b>{threshold}</b><br>
      Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}
    </div>
  </div>
  <div class="footer">
    Vuln Bank · Risk-Aware DevSecOps Dashboard
  </div>
</body>
</html>
"""
    (outdir / "index.html").write_text(html, encoding="utf-8")

# ---------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------
def render_overview(df, threshold, outdir):
    fig = px.bar(
        df.head(10),
        x="cve",
        y="priority_score",
        title="Top 10 Risk Priority"
    )
    fig.write_html(outdir / "top_risks.html", include_plotlyjs="cdn")

    render_template(
        "index.html.j2",
        outdir / "index.html",
        generated=datetime.utcnow(),
        threshold=threshold,
        risk_count=len(df),
        max_score=df["priority_score"].max(),
    )

def render_risks(df, outdir):
    render_template(
        "risks.html.j2",
        outdir / "risks.html",
        rows=df.to_dict(orient="records"),
    )

def render_packages(df, outdir):
    grouped = (
        df.groupby("pkg_name")
        .agg(
            count=("cve", "count"),
            max_priority=("priority_score", "max"),
        )
        .reset_index()
        .sort_values("max_priority", ascending=False)
        .to_dict(orient="records")
    )

    render_template(
        "packages.html.j2",
        outdir / "packages.html",
        packages=grouped,
    )

def render_history(history, outdir):
    if history.empty:
        render_template(
            "history.html.j2",
            outdir / "history.html",
            chart=None,
        )
        return

    history["timestamp"] = pd.to_datetime(history["timestamp"])
    fig = px.line(
        history,
        x="timestamp",
        y="max_epss",
        title="Max EPSS Over Time",
    )
    fig.write_html(outdir / "history_chart.html", include_plotlyjs="cdn")

    render_template(
        "history.html.j2",
        outdir / "history.html",
        chart="history_chart.html",
    )

# ---------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------
def main():
    args = parse_args()
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    df, threshold = load_findings(args.input)
    history = load_history()

    # ✅ CLEAN SCAN PATH
    if df.empty:
        render_clean_dashboard(outdir, threshold)
        print("[OK] Clean scan — green KPI dashboard generated")
        return

    # 🔥 NORMAL PATH
    render_overview(df, threshold, outdir)
    render_risks(df, outdir)
    render_packages(df, outdir)
    render_history(history, outdir)

    print(f"[OK] Dashboard generated in {outdir}")

if __name__ == "__main__":
    main()
