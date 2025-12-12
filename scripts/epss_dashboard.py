#!/usr/bin/env python3
"""
EPSS / KEV Security Dashboard Generator (Enterprise Grade)

Inputs:
  --input   security-reports/epss-findings.json
  --outdir  site/

Outputs:
  site/
    index.html
    risks.html
    packages.html
    history.html
"""

import argparse
import json
from pathlib import Path
from datetime import datetime

import pandas as pd
import plotly.express as px
from jinja2 import Environment, FileSystemLoader

# ------------------------------------------------------------
# CLI
# ------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--outdir", required=True)
    return p.parse_args()

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def safe_series(df, col, default=0):
    if col in df.columns:
        return df[col].fillna(default)
    return pd.Series([default] * len(df))

def compute_priority(row):
    epss = float(row.get("epss", 0)) * 100 * 0.5
    cvss = float(row.get("cvss", 0) or 0) * 10 * 0.3
    kev  = 20 if row.get("is_kev") else 0
    sev  = 10 if row.get("severity") == "CRITICAL" else 0
    return round(epss + cvss + kev + sev, 2)

# ------------------------------------------------------------
# Load Data
# ------------------------------------------------------------
def load_findings(path):
    with open(path) as f:
        data = json.load(f)

    rows = data.get("high_risk", [])
    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    df["priority_score"] = df.apply(compute_priority, axis=1)
    return df.sort_values("priority_score", ascending=False)

def load_history(outdir):
    hist = Path(outdir).parent / "security-reports" / "epss-history.jsonl"
    if not hist.exists():
        return pd.DataFrame()

    return pd.read_json(hist, lines=True)

# ------------------------------------------------------------
# Rendering
# ------------------------------------------------------------
def render(template, out, **ctx):
    env = Environment(loader=FileSystemLoader("templates"))
    tpl = env.get_template(template)
    Path(out).write_text(tpl.render(**ctx), encoding="utf-8")

# ------------------------------------------------------------
# Pages
# ------------------------------------------------------------
def render_overview(df, history, outdir):
    risk_count = len(df)
    max_score = df["priority_score"].max() if not df.empty else 0

    fig = px.bar(
        df.head(10),
        x="cve",
        y="priority_score",
        title="Top 10 Risk Priority",
    )
    fig.write_html(Path(outdir) / "top_risks.html", include_plotlyjs="cdn")

    render(
        "index.html.j2",
        Path(outdir) / "index.html",
        generated=datetime.utcnow(),
        risk_count=risk_count,
        max_score=max_score,
    )

def render_risks(df, outdir):
    render(
        "risks.html.j2",
        Path(outdir) / "risks.html",
        rows=df.to_dict(orient="records"),
    )

def render_packages(df, outdir):
    if df.empty:
        grouped = []
    else:
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

    render(
        "packages.html.j2",
        Path(outdir) / "packages.html",
        packages=grouped,
    )

def render_history(history, outdir):
    if history.empty:
        render("history.html.j2", Path(outdir) / "history.html", chart=None)
        return

    history["timestamp"] = pd.to_datetime(history["timestamp"])
    fig = px.line(
        history,
        x="timestamp",
        y=safe_series(history, "max_epss"),
        title="Max EPSS Over Time",
    )
    fig.write_html(Path(outdir) / "history_chart.html", include_plotlyjs="cdn")

    render(
        "history.html.j2",
        Path(outdir) / "history.html",
        chart="history_chart.html",
    )

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
def main():
    args = parse_args()
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    df = load_findings(args.input)
    history = load_history(outdir)

    render_overview(df, history, outdir)
    render_risks(df, outdir)
    render_packages(df, outdir)
    render_history(history, outdir)

    print(f"[OK] Dashboard generated in {outdir}")

if __name__ == "__main__":
    main()
