#!/usr/bin/env python3
"""
EPSS Dashboard v3 – Vuln Bank

- Reads  : security-reports/epss-findings.json (from epss_gate.py)
           security-reports/epss-history.jsonl (optional)
- Writes : site/index.html        -> Overview (CVE-level)
           site/packages.html     -> Package-level aggregation

Features:
- Dark mode toggle (persisted via localStorage)
- EPSS + CISA KEV summary cards
- CVSS v3 integration (optional, if present)
- EPSS gauge + ranking bar chart
- Historical EPSS trend (if history exists)
- Group-by-package table + chart
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from jinja2 import Template

# -------------------------------------------------------------------
# Paths
# -------------------------------------------------------------------
INPUT_FILE = "security-reports/epss-findings.json"
HISTORY_FILE = "security-reports/epss-history.jsonl"
OUTPUT_DIR = Path("site")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

OVERVIEW_HTML = OUTPUT_DIR / "index.html"
PACKAGES_HTML = OUTPUT_DIR / "packages.html"


# -------------------------------------------------------------------
# Load main findings
# -------------------------------------------------------------------
if not os.path.exists(INPUT_FILE):
    raise FileNotFoundError(f"Missing EPSS output: {INPUT_FILE}")

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    findings = json.load(f)

threshold = float(findings.get("threshold", 0.5))
vulns: List[Dict[str, Any]] = findings.get("high_risk", [])
total_from_trivy = int(findings.get("total_high_crit_from_trivy", 0))

df = pd.DataFrame(vulns) if vulns else pd.DataFrame()

# Ensure columns exist
for col, default in [
    ("epss", 0.0),
    ("cvss", None),
    ("severity", ""),
    ("is_kev", False),
    ("pkg_name", "unknown"),
]:
    if col not in df.columns:
        df[col] = default

# Normalise types
if not df.empty:
    df["epss"] = pd.to_numeric(df["epss"], errors="coerce").fillna(0.0)
    df["cvss"] = pd.to_numeric(df["cvss"], errors="coerce")
    df["is_kev"] = df["is_kev"].fillna(False).astype(bool)
    df["severity"] = df["severity"].fillna("").astype(str).str.upper()

# -------------------------------------------------------------------
# Summary metrics
# -------------------------------------------------------------------
max_epss = float(df["epss"].max()) if not df.empty else 0.0
kev_count = int(df["is_kev"].sum()) if not df.empty else 0
avg_cvss = float(df["cvss"].mean()) if (not df.empty and df["cvss"].notna().any()) else 0.0

# -------------------------------------------------------------------
# Charts – Overview
# -------------------------------------------------------------------
if not df.empty:
    df_sorted = df.sort_values("epss", ascending=False)

    bar_fig = px.bar(
        df_sorted,
        x="cve",
        y="epss",
        color="is_kev",
        title="EPSS Score Ranking per CVE",
        color_discrete_map={True: "red", False: "blue"},
        hover_data=["pkg_name", "installed_version", "fixed_version", "cvss"],
    )
    epss_bar_chart = bar_fig.to_html(include_plotlyjs="cdn", full_html=False)
else:
    epss_bar_chart = "<p class='text-muted'>No high-risk vulnerabilities available.</p>"

gauge_fig = go.Figure(
    go.Indicator(
        mode="gauge+number",
        value=max_epss * 100,
        title={"text": "Highest EPSS (%)"},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": "red" if max_epss >= threshold else "blue"},
        },
    )
)
epss_gauge = gauge_fig.to_html(include_plotlyjs=False, full_html=False)

# -------------------------------------------------------------------
# Historical Trend (optional)
# -------------------------------------------------------------------
trend_chart_html = "<p class='text-muted mb-0'>No history data available.</p>"

if os.path.exists(HISTORY_FILE):
    rows: List[Dict[str, Any]] = []
    with open(HISTORY_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if rows:
        hist_df = pd.DataFrame(rows)
        if "timestamp" in hist_df.columns and "max_epss" in hist_df.columns:
            trend_fig = px.line(
                hist_df.sort_values("timestamp"),
                x="timestamp",
                y="max_epss",
                title="Max EPSS Trend Over Time",
                markers=True,
            )
            trend_chart_html = trend_fig.to_html(include_plotlyjs=False, full_html=False)

# -------------------------------------------------------------------
# Group-by-package view
# -------------------------------------------------------------------
package_chart_html = "<p class='text-muted mb-0'>No package data available.</p>"
package_rows_html = ""

if not df.empty:
    pkg_df = (
        df.groupby("pkg_name", dropna=False)
        .agg(
            vuln_count=("cve", "nunique"),
            max_epss=("epss", "max"),
            max_cvss=("cvss", "max"),
            kev_count=("is_kev", "sum"),
        )
        .reset_index()
        .sort_values("max_epss", ascending=False)
    )

    # Chart: max EPSS per package
    pkg_fig = px.bar(
        pkg_df,
        x="pkg_name",
        y="max_epss",
        color="kev_count",
        title="Max EPSS per Package",
        labels={"kev_count": "KEV Count"},
    )
    package_chart_html = pkg_fig.to_html(include_plotlyjs="cdn", full_html=False)

    # Table rows
    for _, row in pkg_df.iterrows():
        pkg_name = row["pkg_name"]
        vuln_count = int(row["vuln_count"])
        max_epss_pkg = float(row["max_epss"])
        max_cvss_pkg = row["max_cvss"]
        kev_count_pkg = int(row["kev_count"])

        kev_badge = (
            f'<span class="badge bg-danger">{kev_count_pkg} KEV</span>'
            if kev_count_pkg > 0
            else '<span class="badge bg-secondary">0 KEV</span>'
        )
        cvss_txt = f"{max_cvss_pkg:.1f}" if pd.notna(max_cvss_pkg) else "-"

        package_rows_html += f"""
        <tr>
            <td>{pkg_name}</td>
            <td>{vuln_count}</td>
            <td>{max_epss_pkg:.3f}</td>
            <td>{cvss_txt}</td>
            <td>{kev_badge}</td>
        </tr>
        """

if not package_rows_html:
    package_rows_html = (
        "<tr><td colspan='5' class='text-center text-muted'>No data.</td></tr>"
    )

# -------------------------------------------------------------------
# Risk table (CVE-level)
# -------------------------------------------------------------------
def severity_badge(sev: str) -> str:
    sev = (sev or "").upper()
    mapping = {
        "CRITICAL": "danger",
        "HIGH": "warning",
        "MEDIUM": "info",
        "LOW": "secondary",
    }
    return f'<span class="badge bg-{mapping.get(sev, "secondary")}">{sev}</span>'


risk_rows_html = ""
for v in vulns:
    cve = v.get("cve")
    severity = v.get("severity", "")
    epss_score = float(v.get("epss", 0.0) or 0.0)
    cvss_score = v.get("cvss")
    is_kev = bool(v.get("is_kev", False))

    kev_flag = "Yes" if is_kev else "No"
    kev_class = "text-danger fw-bold" if is_kev else "text-muted"

    pkg_name = v.get("pkg_name", "unknown")
    installed = v.get("installed_version", "?")
    fixed = v.get("fixed_version", "N/A")
    desc = (v.get("description") or "")[:160]

    nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "#"
    cvss_txt = f"{float(cvss_score):.1f}" if cvss_score is not None else "-"

    risk_rows_html += f"""
    <tr>
        <td><a href="{nvd_link}" target="_blank" rel="noopener noreferrer">{cve}</a></td>
        <td>{severity_badge(severity)}</td>
        <td>{epss_score:.3f}</td>
        <td>{cvss_txt}</td>
        <td class="{kev_class}">{kev_flag}</td>
        <td>{pkg_name} ({installed} → {fixed})</td>
        <td>{desc}...</td>
    </tr>
    """

if not risk_rows_html:
    risk_rows_html = "<tr><td colspan='7' class='text-center text-muted'>No high-risk vulnerabilities.</td></tr>"

# -------------------------------------------------------------------
# Base HTML template with dark-mode toggle + nav
# -------------------------------------------------------------------
BASE_TEMPLATE = Template(
    r"""
<!doctype html>
<html lang="en" data-bs-theme="light">
<head>
  <meta charset="utf-8">
  <title>{{ title }}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link
    href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css"
    rel="stylesheet">
  <script src="https://cdn.plot.ly/plotly-2.35.2.min.js"></script>
  <style>
    body { background-color: #f7f9fc; }
    .navbar-brand { font-weight: 600; }
    .card-custom { border-radius: 12px; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg bg-body-tertiary border-bottom">
  <div class="container-fluid">
    <a class="navbar-brand" href="index.html">EPSS / KEV – Vuln Bank</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse"
      data-bs-target="#navbarSupportedContent">
      <span class="navbar-toggler-icon"></span>
    </button>

    <div class="collapse navbar-collapse" id="navbarSupportedContent">
      <ul class="navbar-nav me-auto mb-2 mb-lg-0">
        <li class="nav-item">
          <a class="nav-link {% if active_page == 'overview' %}active{% endif %}"
             href="index.html">Overview</a>
        </li>
        <li class="nav-item">
          <a class="nav-link {% if active_page == 'packages' %}active{% endif %}"
             href="packages.html">By Package</a>
        </li>
      </ul>

      <!-- Dark mode toggle -->
      <div class="form-check form-switch">
        <input class="form-check-input" type="checkbox" role="switch" id="themeToggle">
        <label class="form-check-label" for="themeToggle">Dark mode</label>
      </div>
    </div>
  </div>
</nav>

<div class="container py-4">
  {{ body | safe }}
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
// Simple light/dark theme toggle based on Bootstrap 5.3 data-bs-theme
(function() {
  const storedTheme = localStorage.getItem('vb_theme') || 'light';
  const root = document.documentElement;
  root.setAttribute('data-bs-theme', storedTheme);

  const toggle = document.getElementById('themeToggle');
  if (toggle) {
    toggle.checked = storedTheme === 'dark';
    toggle.addEventListener('change', function() {
      const newTheme = this.checked ? 'dark' : 'light';
      root.setAttribute('data-bs-theme', newTheme);
      localStorage.setItem('vb_theme', newTheme);
    });
  }
})();
</script>

</body>
</html>
"""
)

# -------------------------------------------------------------------
# Page bodies
# -------------------------------------------------------------------
overview_body = Template(
    r"""
<div class="mb-4">
  <h1 class="h3">Overview – EPSS / KEV / CVSS</h1>
  <p class="text-muted mb-0">
    Risk-aware view of high/critical vulnerabilities discovered by Trivy SCA, prioritised using EPSS and
    CISA Known Exploited Vulnerabilities (KEV).
  </p>
</div>

<div class="row mb-4">
  <div class="col-md-3">
    <div class="card card-custom shadow-sm p-3">
      <h6>Total High/Critical (Trivy)</h6>
      <h2>{{ total_from_trivy }}</h2>
    </div>
  </div>
  <div class="col-md-3">
    <div class="card card-custom shadow-sm p-3">
      <h6>High-Risk (EPSS / KEV)</h6>
      <h2>{{ high_risk_count }}</h2>
    </div>
  </div>
  <div class="col-md-3">
    <div class="card card-custom shadow-sm p-3">
      <h6>EPSS Threshold</h6>
      <h2>{{ threshold }}</h2>
    </div>
  </div>
  <div class="col-md-3">
    <div class="card card-custom shadow-sm p-3">
      <h6>KEV Findings</h6>
      <h2>{{ kev_count }}</h2>
    </div>
  </div>
</div>

<div class="row mb-4">
  <div class="col-md-6 mb-3 mb-md-0">
    <div class="card card-custom shadow-sm p-3">
      <h5 class="card-title">EPSS Risk Indicator</h5>
      {{ epss_gauge | safe }}
    </div>
  </div>
  <div class="col-md-6">
    <div class="card card-custom shadow-sm p-3">
      <h5 class="card-title">EPSS Score Ranking (CVE)</h5>
      {{ epss_bar_chart | safe }}
    </div>
  </div>
</div>

<div class="card card-custom shadow-sm p-3 mb-4">
  <h5 class="card-title">EPSS Trend (Historical Max)</h5>
  {{ trend_chart | safe }}
</div>

<div class="card card-custom shadow-sm p-3">
  <h5 class="card-title mb-3">High-Risk Vulnerabilities (CVE-level)</h5>
  <div class="table-responsive">
    <table class="table table-striped table-hover align-middle">
      <thead>
        <tr>
          <th>CVE</th>
          <th>Severity</th>
          <th>EPSS</th>
          <th>CVSS v3</th>
          <th>KEV</th>
          <th>Package / Version</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        {{ risk_rows | safe }}
      </tbody>
    </table>
  </div>
</div>
"""
).render(
    total_from_trivy=total_from_trivy,
    high_risk_count=len(vulns),
    threshold=threshold,
    kev_count=kev_count,
    epss_gauge=epss_gauge,
    epss_bar_chart=epss_bar_chart,
    trend_chart=trend_chart_html,
    risk_rows=risk_rows_html,
)

packages_body = Template(
    r"""
<div class="mb-4">
  <h1 class="h3">By Package – Aggregated Risk View</h1>
  <p class="text-muted mb-0">
    Grouping high-risk vulnerabilities by package to support patch planning, ownership assignment,
    and blast-radius analysis.
  </p>
</div>

<div class="row mb-4">
  <div class="col-md-4">
    <div class="card card-custom shadow-sm p-3">
      <h6>Distinct Packages</h6>
      <h2>{{ package_count }}</h2>
    </div>
  </div>
  <div class="col-md-4">
    <div class="card card-custom shadow-sm p-3">
      <h6>Avg CVSS (High-Risk)</h6>
      <h2>{{ avg_cvss }}</h2>
    </div>
  </div>
  <div class="col-md-4">
    <div class="card card-custom shadow-sm p-3">
      <h6>KEV Packages</h6>
      <h2>{{ kev_pkg_count }}</h2>
    </div>
  </div>
</div>

<div class="card card-custom shadow-sm p-3 mb-4">
  <h5 class="card-title">Max EPSS per Package</h5>
  {{ package_chart | safe }}
</div>

<div class="card card-custom shadow-sm p-3">
  <h5 class="card-title mb-3">Package Risk Table</h5>
  <div class="table-responsive">
    <table class="table table-striped table-hover align-middle">
      <thead>
        <tr>
          <th>Package</th>
          <th>High-Risk CVEs</th>
          <th>Max EPSS</th>
          <th>Max CVSS v3</th>
          <th>KEV Count</th>
        </tr>
      </thead>
      <tbody>
        {{ package_rows | safe }}
      </tbody>
    </table>
  </div>
</div>
"""
).render(
    package_count=int(df["pkg_name"].nunique()) if not df.empty else 0,
    avg_cvss=round(avg_cvss, 2),
    kev_pkg_count=int(
        df.groupby("pkg_name")["is_kev"].any().sum()
    ) if not df.empty else 0,
    package_chart=package_chart_html,
    package_rows=package_rows_html,
)

# -------------------------------------------------------------------
# Render final HTML pages
# -------------------------------------------------------------------
overview_html = BASE_TEMPLATE.render(
    title="EPSS / KEV Dashboard – Vuln Bank (Overview)",
    active_page="overview",
    body=overview_body,
)
OVERVIEW_HTML.write_text(overview_html, encoding="utf-8")

packages_html = BASE_TEMPLATE.render(
    title="EPSS / KEV Dashboard – Vuln Bank (By Package)",
    active_page="packages",
    body=packages_body,
)
PACKAGES_HTML.write_text(packages_html, encoding="utf-8")

print(f"[OK] Generated: {OVERVIEW_HTML}")
print(f"[OK] Generated: {PACKAGES_HTML}")
