#!/usr/bin/env python3
"""
EPSS / KEV / CVSS Dashboard Generator for Vuln Bank

Input:
  - --input  : JSON file from epss_gate.py (e.g. security-reports/epss-findings.json)
  - --outdir : Output directory for static site (e.g. site)

Output:
  - index.html      (overview)
  - kev.html        (CISA KEV focused view)
  - packages.html   (group-by package view)
  - cvss.html       (CVSS focused view)
  - history.html    (trend view using epss-history.jsonl if present)

Data model (per item in high_risk[]):
  {
    "cve": str,
    "pkg_name": str,
    "installed_version": str,
    "fixed_version": str,
    "severity": "HIGH"|"CRITICAL"|...,
    "description": str,
    "target": str,
    "cvss": float | None,
    "epss": float,
    "percentile": float,
    "is_kev": bool,
    "reasons": [str, ...],
    "priority_score": float (optional – will be computed if missing)
  }

Priority scoring model (0–100):
  severity_factor: CRITICAL=1.0, HIGH=0.7, MEDIUM=0.4, LOW=0.2, else=0.2
  epss_norm  = epss in [0,1]
  cvss_norm  = (cvss or 0) / 10
  base = 0.5*epss_norm + 0.3*cvss_norm + 0.2*severity_factor
  if is_kev: base += 0.2
  priority_score = min(base * 100, 100)

You can tune the scoring weights if needed.
"""

import argparse
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate EPSS / KEV dashboard")
    parser.add_argument(
        "--input",
        required=True,
        help="EPSS findings JSON (output from epss_gate.py)",
    )
    parser.add_argument(
        "--outdir",
        required=True,
        help="Output directory for static dashboard (e.g. site)",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Data loading & transformation
# ---------------------------------------------------------------------------

def load_epss_findings(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"EPSS findings not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if "high_risk" not in data:
        data["high_risk"] = []

    return data


def severity_factor(sev: str) -> float:
    s = (sev or "").upper()
    if s == "CRITICAL":
        return 1.0
    if s == "HIGH":
        return 0.7
    if s == "MEDIUM":
        return 0.4
    if s == "LOW":
        return 0.2
    return 0.2


def ensure_priority_score(row: Dict[str, Any]) -> float:
    """
    Compute priority_score if not present or invalid.
    Result is in range [0, 100].
    """
    existing = row.get("priority_score")
    try:
        if existing is not None:
            val = float(existing)
            if 0 <= val <= 100:
                return val
    except (TypeError, ValueError):
        pass

    epss = float(row.get("epss") or 0.0)
    cvss = row.get("cvss")
    try:
        cvss = float(cvss) if cvss is not None else 0.0
    except (TypeError, ValueError):
        cvss = 0.0

    sev_factor = severity_factor(row.get("severity", ""))
    epss_norm = max(0.0, min(epss, 1.0))
    cvss_norm = max(0.0, min(cvss / 10.0, 1.0))
    base = 0.5 * epss_norm + 0.3 * cvss_norm + 0.2 * sev_factor

    is_kev = bool(row.get("is_kev"))
    if is_kev:
        base += 0.2  # bonus for KEV

    score = max(0.0, min(base * 100.0, 100.0))
    return round(score, 1)


def build_dataframe(data: Dict[str, Any]) -> pd.DataFrame:
    vulns = data.get("high_risk", []) or []

    # Normalize + ensure priority_score
    normalized: List[Dict[str, Any]] = []
    for item in vulns:
        item = dict(item)  # shallow copy
        item["priority_score"] = ensure_priority_score(item)
        item["epss"] = float(item.get("epss") or 0.0)
        item["percentile"] = float(item.get("percentile") or 0.0)
        cvss = item.get("cvss")
        try:
            item["cvss"] = float(cvss) if cvss is not None else None
        except (TypeError, ValueError):
            item["cvss"] = None

        item["is_kev"] = bool(item.get("is_kev"))
        item["severity"] = (item.get("severity") or "").upper()
        item["description"] = (item.get("description") or "")[:400]
        item["pkg_name"] = item.get("pkg_name") or "-"
        item["installed_version"] = item.get("installed_version") or "-"
        item["fixed_version"] = item.get("fixed_version") or "-"
        item["target"] = item.get("target") or "-"

        normalized.append(item)

    if not normalized:
        return pd.DataFrame(columns=[
            "cve",
            "pkg_name",
            "installed_version",
            "fixed_version",
            "severity",
            "description",
            "target",
            "cvss",
            "epss",
            "percentile",
            "is_kev",
            "priority_score",
            "reasons",
        ])

    df = pd.DataFrame(normalized)
    # Ensure columns exist
    for col in [
        "cve", "pkg_name", "installed_version", "fixed_version", "severity",
        "description", "target", "cvss", "epss", "percentile", "is_kev",
        "priority_score", "reasons",
    ]:
        if col not in df.columns:
            df[col] = None

    return df


def load_history(epss_file: Path) -> Optional[pd.DataFrame]:
    hist_path = epss_file.parent / "epss-history.jsonl"
    if not hist_path.is_file():
        return None

    records: List[Dict[str, Any]] = []
    with hist_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                records.append(rec)
            except json.JSONDecodeError:
                continue

    if not records:
        return None

    df = pd.DataFrame(records)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.sort_values("timestamp")
    return df


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

BASE_CSS = r"""
:root {
  color-scheme: light dark;
  --bg: #0f172a;
  --bg-soft: #020617;
  --bg-card: #020617;
  --bg-card-soft: #0b1220;
  --border-subtle: #1e293b;
  --text-main: #e5e7eb;
  --text-muted: #9ca3af;
  --accent: #22c55e;
  --accent-soft: rgba(34,197,94,0.12);
  --danger: #f97373;
  --danger-soft: rgba(248,113,113,0.15);
  --warning: #facc15;
  --warning-soft: rgba(250,204,21,0.15);
  --shadow-soft: 0 18px 35px rgba(15,23,42,0.7);
  --radius-lg: 18px;
  --radius-pill: 999px;
}

:root[data-theme='light'] {
  --bg: #f9fafb;
  --bg-soft: #e5e7eb;
  --bg-card: #ffffff;
  --bg-card-soft: #f3f4f6;
  --border-subtle: #e5e7eb;
  --text-main: #0f172a;
  --text-muted: #6b7280;
  --accent: #16a34a;
  --accent-soft: rgba(22,163,74,0.1);
  --danger: #dc2626;
  --danger-soft: rgba(220,38,38,0.12);
  --warning: #d97706;
  --warning-soft: rgba(217,119,6,0.12);
  --shadow-soft: 0 18px 35px rgba(15,23,42,0.10);
}

*,
*::before,
*::after {
  box-sizing: border-box;
}

body {
  margin: 0;
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text",
    "Inter", "Segoe UI", sans-serif;
  background: radial-gradient(circle at top left, #1f2937 0, var(--bg) 55%);
  color: var(--text-main);
  min-height: 100vh;
}

.app-shell {
  max-width: 1200px;
  margin: 0 auto;
  padding: 24px 20px 40px;
}

/* Header / navbar */
.navbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 22px;
  gap: 12px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 12px;
}

.brand-badge {
  width: 32px;
  height: 32px;
  border-radius: 12px;
  background: radial-gradient(circle at 20% 0, #4ade80, #15803d);
  display: flex;
  align-items: center;
  justify-content: center;
  color: #ecfdf5;
  font-size: 18px;
  font-weight: 700;
  box-shadow: 0 12px 25px rgba(34,197,94,0.5);
}

.brand-text-title {
  font-size: 18px;
  font-weight: 600;
}

.brand-text-sub {
  font-size: 11px;
  color: var(--text-muted);
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

/* Nav tabs */
.nav-tabs {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 3px;
  border-radius: 999px;
  background: rgba(15,23,42,0.8);
  border: 1px solid rgba(148,163,184,0.35);
  box-shadow: 0 12px 25px rgba(15,23,42,0.85);
}

.nav-tab {
  border: none;
  border-radius: 999px;
  padding: 6px 12px;
  font-size: 11px;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  font-weight: 500;
  color: var(--text-muted);
  background: transparent;
  cursor: pointer;
  transition: all 0.14s ease;
}

.nav-tab a {
  color: inherit;
  text-decoration: none;
}

.nav-tab-active {
  background: linear-gradient(135deg, #22c55e, #4ade80);
  color: #022c22;
  box-shadow: 0 10px 25px rgba(34,197,94,0.5);
}

/* Toggle */
.toggle {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  border-radius: 999px;
  border: 1px solid rgba(148,163,184,0.5);
  background: rgba(15,23,42,0.9);
  padding: 4px 10px;
  font-size: 11px;
  color: var(--text-muted);
  cursor: pointer;
  user-select: none;
}

.toggle-circle {
  width: 14px;
  height: 14px;
  border-radius: 999px;
  background: linear-gradient(135deg, #22c55e, #4ade80);
}

/* Grid layout */
.grid {
  display: grid;
  gap: 16px;
}

.grid-3 {
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
}

.grid-2 {
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
}

/* Cards */
.card {
  background: radial-gradient(circle at top left, rgba(15,23,42,0.5), var(--bg-card));
  border-radius: var(--radius-lg);
  border: 1px solid rgba(148,163,184,0.35);
  box-shadow: var(--shadow-soft);
  padding: 14px 16px 16px;
  position: relative;
  overflow: hidden;
}

.card-title-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 4px;
}

.card-title {
  font-size: 13px;
  font-weight: 500;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 0.06em;
}

.badge-soft {
  font-size: 11px;
  padding: 2px 8px;
  border-radius: 999px;
  border: 1px solid rgba(148,163,184,0.5);
  color: var(--text-muted);
}

.card-value {
  font-size: 24px;
  font-weight: 600;
}

.card-sub {
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 1px;
}

/* severity pills */
.sev-pill {
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 500;
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.sev-critical {
  background: var(--danger-soft);
  color: var(--danger);
}

.sev-high {
  background: var(--warning-soft);
  color: var(--warning);
}

.sev-other {
  background: rgba(59,130,246,0.12);
  color: #60a5fa;
}

/* table */
.table-wrap {
  overflow: auto;
  margin-top: 8px;
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12px;
  min-width: 720px;
}

thead tr {
  background: rgba(15,23,42,0.8);
}

th, td {
  padding: 6px 8px;
  text-align: left;
  border-bottom: 1px solid rgba(30,64,175,0.45);
}

th {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-muted);
  cursor: pointer;
}

tbody tr:hover {
  background: rgba(15,23,42,0.7);
}

.muted {
  color: var(--text-muted);
  font-size: 11px;
}

.chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 11px;
  background: var(--accent-soft);
  color: var(--accent);
}

.chip-badge {
  width: 6px;
  height: 6px;
  border-radius: 999px;
  background: var(--accent);
}

.priority-pill {
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 500;
  background: rgba(34,197,94,0.1);
  color: var(--accent);
}

/* chart container */
.chart {
  width: 100%;
  height: 260px;
}

/* small */
.small {
  font-size: 11px;
}
"""

BASE_JS = r"""
// Dark mode toggle
(function() {
  const root = document.documentElement;
  const saved = localStorage.getItem("vulnbank-theme");
  if (saved === "light" || saved === "dark") {
    root.setAttribute("data-theme", saved);
  }
  const toggle = document.getElementById("theme-toggle");
  if (toggle) {
    toggle.addEventListener("click", () => {
      const current = root.getAttribute("data-theme") === "light" ? "dark" : "light";
      root.setAttribute("data-theme", current);
      localStorage.setItem("vulnbank-theme", current);
    });
  }
})();

// Simple table sorting
function sortTable(tableId, colIndex, numeric=false, desc=false) {
  const table = document.getElementById(tableId);
  if (!table) return;
  const tbody = table.tBodies[0];
  const rows = Array.from(tbody.querySelectorAll("tr"));
  rows.sort((a, b) => {
    let av = a.children[colIndex].dataset.sort || a.children[colIndex].innerText;
    let bv = b.children[colIndex].dataset.sort || b.children[colIndex].innerText;
    if (numeric) {
      av = parseFloat(av) || 0;
      bv = parseFloat(bv) || 0;
    } else {
      av = av.toString().toLowerCase();
      bv = bv.toString().toLowerCase();
    }
    if (av < bv) return desc ? 1 : -1;
    if (av > bv) return desc ? -1 : 1;
    return 0;
  });
  rows.forEach(r => tbody.appendChild(r));
}
"""


def render_base_html(title: str, active_page: str, body_html: str) -> str:
    """Wraps provided body_html into full HTML skeleton."""
    def nav_tab(page: str, label: str) -> str:
        cls = "nav-tab nav-tab-active" if page == active_page else "nav-tab"
        href = {
            "overview": "index.html",
            "kev": "kev.html",
            "packages": "packages.html",
            "cvss": "cvss.html",
            "history": "history.html",
        }[page]
        return f'<button class="{cls}"><a href="{href}">{label}</a></button>'

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>{title}</title>
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <style>{BASE_CSS}</style>
</head>
<body>
  <div class="app-shell">
    <header class="navbar">
      <div class="brand">
        <div class="brand-badge">V</div>
        <div>
          <div class="brand-text-title">Vuln Bank – Risk-aware DevSecOps</div>
          <div class="brand-text-sub">EPSS / KEV / CVSS Risk Dashboard</div>
        </div>
      </div>
      <div style="display:flex;align-items:center;gap:10px;">
        <div class="nav-tabs">
          {nav_tab("overview", "Overview")}
          {nav_tab("kev", "CISA KEV")}
          {nav_tab("packages", "Packages")}
          {nav_tab("cvss", "CVSS & Impact")}
          {nav_tab("history", "History")}
        </div>
        <div id="theme-toggle" class="toggle">
          <div class="toggle-circle"></div>
          <span>Dark / Light</span>
        </div>
      </div>
    </header>

    {body_html}
  </div>
  <script>{BASE_JS}</script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Page renderers
# ---------------------------------------------------------------------------

def render_kpi_cards(df: pd.DataFrame, meta: Dict[str, Any]) -> str:
    total_high_crit = int(meta.get("total_trivy_high_crit") or 0)
    high_risk_count = int(len(df))
    kev_count = int(df["is_kev"].sum()) if not df.empty and "is_kev" in df else 0
    avg_epss = float(df["epss"].mean()) if not df.empty else 0.0
    max_epss = float(df["epss"].max()) if not df.empty else 0.0
    avg_priority = float(df["priority_score"].mean()) if not df.empty else 0.0

    return f"""
<section class="grid grid-3" style="margin-bottom:18px;">
  <article class="card">
    <div class="card-title-row">
      <div class="card-title">High/Critical from Trivy</div>
      <div class="badge-soft">SCA</div>
    </div>
    <div class="card-value">{total_high_crit}</div>
    <div class="card-sub">All HIGH/CRITICAL detected in dependencies</div>
  </article>

  <article class="card">
    <div class="card-title-row">
      <div class="card-title">Prioritized risks</div>
      <div class="badge-soft">EPSS / KEV filtered</div>
    </div>
    <div class="card-value">{high_risk_count}</div>
    <div class="card-sub">After EPSS ≥ {meta.get("threshold", 0)} or CISA KEV</div>
  </article>

  <article class="card">
    <div class="card-title-row">
      <div class="card-title">KEV & risk index</div>
      <div class="badge-soft">Exploitability</div>
    </div>
    <div class="card-value">{kev_count} KEV</div>
    <div class="card-sub">Avg EPSS {avg_epss:.3f}, Max EPSS {max_epss:.3f}, Avg score {avg_priority:.1f}</div>
  </article>
</section>
"""


def df_to_rows(df: pd.DataFrame, limit: int = 60) -> str:
    if df.empty:
        return "<tbody><tr><td colspan='9' class='muted'>No prioritized vulnerabilities found.</td></tr></tbody>"

    rows = []
    subset = df.sort_values("priority_score", ascending=False).head(limit)

    for _, r in subset.iterrows():
        sev = (r.get("severity") or "").upper()
        if sev == "CRITICAL":
            sev_cls = "sev-pill sev-critical"
        elif sev == "HIGH":
            sev_cls = "sev-pill sev-high"
        else:
            sev_cls = "sev-pill sev-other"

        sev_html = f'<span class="{sev_cls}">{sev or "-"}</span>'

        kev_html = (
            '<span class="chip"><span class="chip-badge"></span> KEV</span>'
            if bool(r.get("is_kev"))
            else '<span class="muted">No</span>'
        )

        priority = float(r.get("priority_score") or 0.0)

        rows.append(
            f"""
<tr>
  <td data-sort="{r.get('cve','')}"><code>{r.get('cve','')}</code></td>
  <td data-sort="{r.get('pkg_name','')}">{r.get('pkg_name','-')}<br/>
      <span class="muted">{r.get('installed_version','-')} → {r.get('fixed_version','-')}</span></td>
  <td>{sev_html}</td>
  <td data-sort="{r.get('epss',0.0):.5f}">{r.get('epss',0.0):.4f}</td>
  <td data-sort="{r.get('cvss') if r.get('cvss') is not None else 0}">{r.get('cvss') if r.get('cvss') is not None else '-'}</td>
  <td data-sort="{r.get('percentile',0.0):.5f}">{r.get('percentile',0.0):.4f}</td>
  <td>{kev_html}</td>
  <td data-sort="{priority:.1f}"><span class="priority-pill">{priority:.1f}</span></td>
  <td><span class="muted small">{(r.get('description') or '')[:120]}</span><br/>
      <span class="small">Target: {r.get('target','-')}</span></td>
</tr>
"""
        )
    return "<tbody>" + "\n".join(rows) + "</tbody>"


def render_overview_page(df: pd.DataFrame, meta: Dict[str, Any], outdir: Path) -> None:
    # Chart data (severity vs count and score)
    if df.empty:
        sev_counts = {}
    else:
        sev_counts = (
            df.groupby("severity")
            .agg(count=("cve", "count"), avg_score=("priority_score", "mean"))
            .reset_index()
        )

    labels = sev_counts["severity"].tolist() if len(sev_counts) else []
    counts = [int(x) for x in sev_counts["count"]] if len(sev_counts) else []
    scores = [round(float(x), 1) for x in sev_counts["avg_score"]] if len(sev_counts) else []

    chart_js = f"""
<script>
(function() {{
  const ctx = document.getElementById('severityChart').getContext('2d');
  const labels = {json.dumps(labels)};
  const counts = {json.dumps(counts)};
  const scores = {json.dumps(scores)};

  if (labels.length === 0) return;

  new Chart(ctx, {{
    type: 'bar',
    data: {{
      labels,
      datasets: [
        {{
          type: 'bar',
          label: 'Count',
          data: counts,
          yAxisID: 'y',
        }},
        {{
          type: 'line',
          label: 'Avg priority score',
          data: scores,
          yAxisID: 'y1',
        }}
      ]
    }},
    options: {{
      responsive: true,
      scales: {{
        y: {{
          beginAtZero: true,
          title: {{ display: true, text: 'Count' }}
        }},
        y1: {{
          position: 'right',
          beginAtZero: true,
          max: 100,
          title: {{ display: true, text: 'Priority score' }},
          grid: {{ drawOnChartArea: false }}
        }}
      }},
      plugins: {{
        legend: {{
          labels: {{
            font: {{ size: 11 }}
          }}
        }}
      }}
    }}
  }});
}})();
</script>
"""

    body = f"""
{render_kpi_cards(df, meta)}

<section class="grid grid-2" style="margin-bottom:20px;">
  <article class="card">
    <div class="card-title-row">
      <div class="card-title">Severity vs Priority</div>
      <div class="badge-soft">Chart</div>
    </div>
    <canvas id="severityChart" class="chart"></canvas>
  </article>

  <article class="card">
    <div class="card-title-row">
      <div class="card-title">Scoring model</div>
      <div class="badge-soft">Priority index (0–100)</div>
    </div>
    <div class="small">
      <p>
        The risk index combines EPSS, CVSS, CISA KEV and severity into a single
        <strong>priority_score</strong> (0–100). It is designed for MR/PR gating
        and remediation order.
      </p>
      <ul>
        <li><strong>EPSS weight</strong>: 0.5 · epss</li>
        <li><strong>CVSS weight</strong>: 0.3 · (cvss/10)</li>
        <li><strong>Severity weight</strong>: 0.2 · severity_factor (Critical/High/…)</li>
        <li><strong>KEV bonus</strong>: +0.2 if in CISA KEV catalog</li>
      </ul>
      <p>
        You can tune this model in <code>epss_gate.py</code> and re-run the pipeline;
        the dashboard will automatically reflect the new scores.
      </p>
    </div>
  </article>
</section>

<article class="card">
  <div class="card-title-row">
    <div class="card-title">Top prioritized vulnerabilities</div>
    <div class="badge-soft">Sorted by priority_score</div>
  </div>
  <div class="table-wrap">
    <table id="table-overview">
      <thead>
        <tr>
          <th onclick="sortTable('table-overview',0,false,false)">CVE</th>
          <th onclick="sortTable('table-overview',1,false,false)">Package</th>
          <th onclick="sortTable('table-overview',2,false,false)">Severity</th>
          <th onclick="sortTable('table-overview',3,true,true)">EPSS</th>
          <th onclick="sortTable('table-overview',4,true,true)">CVSS</th>
          <th onclick="sortTable('table-overview',5,true,true)">EPSS pct</th>
          <th onclick="sortTable('table-overview',6,false,false)">KEV</th>
          <th onclick="sortTable('table-overview',7,true,true)">Score</th>
          <th>Description</th>
        </tr>
      </thead>
      {df_to_rows(df)}
    </table>
  </div>
</article>

{chart_js}
"""

    html = render_base_html("Vuln Bank – EPSS / KEV Dashboard", "overview", body)
    (outdir / "index.html").write_text(html, encoding="utf-8")


def render_kev_page(df: pd.DataFrame, outdir: Path) -> None:
    kev_df = df[df["is_kev"] == True].copy() if not df.empty else df

    if kev_df.empty:
        summary = "<p class='muted'>No vulnerabilities from CISA KEV catalog in the current run.</p>"
    else:
        summary = f"""
<p class="small">
  Showing <strong>{len(kev_df)}</strong> vulnerabilities that are present in the
  <strong>CISA Known Exploited Vulnerabilities (KEV)</strong> catalog.
</p>
"""

    body = f"""
<section class="card" style="margin-bottom:18px;">
  <div class="card-title-row">
    <div class="card-title">CISA KEV prioritization</div>
    <div class="badge-soft">Exploited in the wild</div>
  </div>
  {summary}
</section>

<article class="card">
  <div class="card-title-row">
    <div class="card-title">KEV vulnerabilities</div>
    <div class="badge-soft">Sorted by priority_score</div>
  </div>
  <div class="table-wrap">
    <table id="table-kev">
      <thead>
        <tr>
          <th onclick="sortTable('table-kev',0,false,false)">CVE</th>
          <th onclick="sortTable('table-kev',1,false,false)">Package</th>
          <th onclick="sortTable('table-kev',2,false,false)">Severity</th>
          <th onclick="sortTable('table-kev',3,true,true)">EPSS</th>
          <th onclick="sortTable('table-kev',4,true,true)">CVSS</th>
          <th onclick="sortTable('table-kev',5,true,true)">Score</th>
          <th>Description</th>
        </tr>
      </thead>
      {df_to_rows(kev_df)}
    </table>
  </div>
</article>
"""

    html = render_base_html("Vuln Bank – CISA KEV View", "kev", body)
    (outdir / "kev.html").write_text(html, encoding="utf-8")


def render_packages_page(df: pd.DataFrame, outdir: Path) -> None:
    if df.empty:
        body = """
<article class="card">
  <div class="card-title-row">
    <div class="card-title">Packages</div>
    <div class="badge-soft">Group by package</div>
  </div>
  <p class="muted">No prioritized vulnerabilities available.</p>
</article>
"""
        html = render_base_html("Vuln Bank – Packages", "packages", body)
        (outdir / "packages.html").write_text(html, encoding="utf-8")
        return

    grp = (
        df.groupby("pkg_name")
        .agg(
            vuln_count=("cve", "count"),
            max_priority=("priority_score", "max"),
            max_epss=("epss", "max"),
        )
        .reset_index()
        .sort_values(["max_priority", "vuln_count"], ascending=[False, False])
    )

    rows = []
    for _, r in grp.iterrows():
        rows.append(
            f"""
<tr>
  <td data-sort="{r['pkg_name']}">{r['pkg_name']}</td>
  <td data-sort="{int(r['vuln_count'])}">{int(r['vuln_count'])}</td>
  <td data-sort="{float(r['max_epss']):.5f}">{float(r['max_epss']):.4f}</td>
  <td data-sort="{float(r['max_priority']):.1f}"><span class="priority-pill">{float(r['max_priority']):.1f}</span></td>
</tr>
"""
        )

    body = f"""
<section class="card" style="margin-bottom:18px;">
  <div class="card-title-row">
    <div class="card-title">Package-level risk</div>
    <div class="badge-soft">Aggregated by package</div>
  </div>
  <p class="small">
    Use this view to prioritize <strong>library upgrades</strong> and track
    which third-party components contribute the most risk to Vuln Bank.
  </p>
</section>

<article class="card">
  <div class="card-title-row">
    <div class="card-title">Packages sorted by risk</div>
    <div class="badge-soft">priority_score + count</div>
  </div>
  <div class="table-wrap">
    <table id="table-packages">
      <thead>
        <tr>
          <th onclick="sortTable('table-packages',0,false,false)">Package</th>
          <th onclick="sortTable('table-packages',1,true,true)">Vulns</th>
          <th onclick="sortTable('table-packages',2,true,true)">Max EPSS</th>
          <th onclick="sortTable('table-packages',3,true,true)">Max score</th>
        </tr>
      </thead>
      <tbody>
        {"".join(rows)}
      </tbody>
    </table>
  </div>
</article>
"""

    html = render_base_html("Vuln Bank – Packages View", "packages", body)
    (outdir / "packages.html").write_text(html, encoding="utf-8")


def render_cvss_page(df: pd.DataFrame, outdir: Path) -> None:
    with_cvss = df[df["cvss"].notnull()] if not df.empty else df

    if with_cvss.empty:
        extra = "<p class='muted'>No CVSS scores available in current findings.</p>"
    else:
        extra = f"<p class='small'>Showing {len(with_cvss)} vulnerabilities that have CVSS scores.</p>"

    # Histogram-like buckets for CVSS
    # 0–4, 4–7, 7–9, 9–10
    if with_cvss.empty:
        buckets = []
    else:
        def bucket(c: float) -> str:
            if c < 4.0:
                return "0–4 (Low)"
            if c < 7.0:
                return "4–7 (Medium)"
            if c < 9.0:
                return "7–9 (High)"
            return "9–10 (Critical)"

        tmp = with_cvss.copy()
        tmp["cvss_bucket"] = tmp["cvss"].apply(bucket)
        buckets_df = tmp.groupby("cvss_bucket").agg(
            count=("cve", "count"),
            avg_score=("priority_score", "mean"),
        ).reset_index().sort_values("cvss_bucket")
        labels = buckets_df["cvss_bucket"].tolist()
        counts = [int(x) for x in buckets_df["count"]]
        scores = [round(float(x), 1) for x in buckets_df["avg_score"]]
    chart_js = f"""
<script>
(function() {{
  const ctx = document.getElementById('cvssChart').getContext('2d');
  const labels = {json.dumps(labels if with_cvss is not None and not with_cvss.empty else [])};
  const counts = {json.dumps(counts if with_cvss is not None and not with_cvss.empty else [])};
  const scores = {json.dumps(scores if with_cvss is not None and not with_cvss.empty else [])};
  if (labels.length === 0) return;
  new Chart(ctx, {{
    type: 'bar',
    data: {{
      labels,
      datasets: [
        {{
          type: 'bar',
          label: 'Count',
          data: counts,
          yAxisID: 'y',
        }},
        {{
          type: 'line',
          label: 'Avg priority score',
          data: scores,
          yAxisID: 'y1',
        }}
      ]
    }},
    options: {{
      responsive: true,
      scales: {{
        y: {{
          beginAtZero: true,
          title: {{ display: true, text: 'Count' }}
        }},
        y1: {{
          position: 'right',
          beginAtZero: true,
          max: 100,
          title: {{ display: true, text: 'Priority score' }},
          grid: {{ drawOnChartArea: false }}
        }}
      }}
    }}
  }});
}})();
</script>
"""

    body = f"""
<section class="grid grid-2" style="margin-bottom:18px;">
  <article class="card">
    <div class="card-title-row">
      <div class="card-title">CVSS vs Priority</div>
      <div class="badge-soft">Impact buckets</div>
    </div>
    {extra}
    <canvas id="cvssChart" class="chart"></canvas>
  </article>

  <article class="card">
    <div class="card-title-row">
      <div class="card-title">Interpretation</div>
      <div class="badge-soft">EPSS + CVSS</div>
    </div>
    <p class="small">
      CVSS captures <strong>impact</strong>, while EPSS captures
      <strong>likelihood of exploitation</strong>. The <code>priority_score</code>
      combines both plus CISA KEV & severity, so you can explain to stakeholders
      why some medium-CVSS issues might outrank high-CVSS ones when exploitability
      is much higher.
    </p>
  </article>
</section>

<article class="card">
  <div class="card-title-row">
    <div class="card-title">Vulnerabilities with CVSS</div>
    <div class="badge-soft">Sorted by priority_score</div>
  </div>
  <div class="table-wrap">
    <table id="table-cvss">
      <thead>
        <tr>
          <th onclick="sortTable('table-cvss',0,false,false)">CVE</th>
          <th onclick="sortTable('table-cvss',1,false,false)">Package</th>
          <th onclick="sortTable('table-cvss',2,true,true)">CVSS</th>
          <th onclick="sortTable('table-cvss',3,true,true)">EPSS</th>
          <th onclick="sortTable('table-cvss',4,true,true)">Score</th>
          <th>Description</th>
        </tr>
      </thead>
      {df_to_rows(with_cvss)}
    </table>
  </div>
</article>

{chart_js}
"""
    html = render_base_html("Vuln Bank – CVSS View", "cvss", body)
    (outdir / "cvss.html").write_text(html, encoding="utf-8")


def render_history_page(hist_df: Optional[pd.DataFrame], outdir: Path) -> None:
    if hist_df is None or hist_df.empty:
        body = """
<article class="card">
  <div class="card-title-row">
    <div class="card-title">History</div>
    <div class="badge-soft">Pipeline runs</div>
  </div>
  <p class="muted">
    No history data found. The gate will populate <code>epss-history.jsonl</code>
    on future CI runs.
  </p>
</article>
"""
        html = render_base_html("Vuln Bank – History", "history", body)
        (outdir / "history.html").write_text(html, encoding="utf-8")
        return

    # Prepare chart data
    ts = hist_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M").fillna("").tolist()
    total = hist_df.get("total_high_crit_from_trivy", hist_df.get("total_trivy_high_crit", 0)).fillna(0).astype(int).tolist()
    epss_high = hist_df.get("epss_high_count", 0).fillna(0).astype(int).tolist()
    kev_count = hist_df.get("kev_count", 0).fillna(0).astype(int).tolist()
    max_epss = hist_df.get("max_epss", 0.0).fillna(0.0).astype(float).tolist()

    chart_js = f"""
<script>
(function() {{
  const ctx = document.getElementById('historyChart').getContext('2d');
  const labels = {json.dumps(ts)};
  const total = {json.dumps(total)};
  const epssHigh = {json.dumps(epss_high)};
  const kev = {json.dumps(kev_count)};
  const maxEpss = {json.dumps(max_epss)};

  if (labels.length === 0) return;

  new Chart(ctx, {{
    data: {{
      labels,
      datasets: [
        {{
          type: 'bar',
          label: 'HIGH/CRITICAL (Trivy)',
          data: total,
          yAxisID: 'y',
        }},
        {{
          type: 'bar',
          label: 'EPSS/KEV high risk',
          data: epssHigh,
          yAxisID: 'y',
        }},
        {{
          type: 'line',
          label: 'KEV count',
          data: kev,
          yAxisID: 'y1',
        }},
        {{
          type: 'line',
          label: 'Max EPSS',
          data: maxEpss,
          yAxisID: 'y2',
        }}
      ]
    }},
    options: {{
      responsive: true,
      scales: {{
        y: {{
          beginAtZero: true,
          title: {{ display: true, text: 'Counts' }}
        }},
        y1: {{
          position: 'right',
          beginAtZero: true,
          title: {{ display: true, text: 'KEV count' }},
          grid: {{ drawOnChartArea: false }}
        }},
        y2: {{
          position: 'right',
          beginAtZero: true,
          max: 1,
          title: {{ display: true, text: 'Max EPSS' }},
          grid: {{ drawOnChartArea: false }}
        }}
      }},
      plugins: {{
        legend: {{
          labels: {{
            font: {{ size: 11 }}
          }}
        }}
      }}
    }}
  }});
}})();
</script>
"""

    # Table rows
    rows = []
    for _, r in hist_df.iterrows():
        ts_str = r.get("timestamp")
        if hasattr(ts_str, "strftime"):
            ts_str = ts_str.strftime("%Y-%m-%d %H:%M:%S")
        total_v = r.get("total_high_crit_from_trivy", r.get("total_trivy_high_crit", 0))
        rows.append(
            f"""
<tr>
  <td>{ts_str}</td>
  <td>{r.get('run_id','-')}</td>
  <td data-sort="{int(total_v)}">{int(total_v)}</td>
  <td data-sort="{int(r.get('epss_high_count',0))}">{int(r.get('epss_high_count',0))}</td>
  <td data-sort="{int(r.get('kev_count',0))}">{int(r.get('kev_count',0))}</td>
  <td data-sort="{float(r.get('max_epss',0.0)):.5f}">{float(r.get('max_epss',0.0)):.4f}</td>
</tr>
"""
        )

    body = f"""
<section class="card" style="margin-bottom:18px;">
  <div class="card-title-row">
    <div class="card-title">Risk trend over time</div>
    <div class="badge-soft">From epss-history.jsonl</div>
  </div>
  <p class="small">
    Every EPSS gate run appends a line to <code>epss-history.jsonl</code>.
    This view lets you demonstrate <strong>risk burn-down</strong> to management:
    fewer EPSS/KEV-high findings and stable or shrinking KEV footprint.
  </p>
  <canvas id="historyChart" class="chart"></canvas>
</section>

<article class="card">
  <div class="card-title-row">
    <div class="card-title">History table</div>
    <div class="badge-soft">One row per gate run</div>
  </div>
  <div class="table-wrap">
    <table id="table-history">
      <thead>
        <tr>
          <th onclick="sortTable('table-history',0,false,false)">Timestamp</th>
          <th onclick="sortTable('table-history',1,false,false)">Run ID</th>
          <th onclick="sortTable('table-history',2,true,true)">Trivy high/crit</th>
          <th onclick="sortTable('table-history',3,true,true)">EPSS/KEV high risk</th>
          <th onclick="sortTable('table-history',4,true,true)">KEV count</th>
          <th onclick="sortTable('table-history',5,true,true)">Max EPSS</th>
        </tr>
      </thead>
      <tbody>
        {"".join(rows)}
      </tbody>
    </table>
  </div>
</article>

{chart_js}
"""

    html = render_base_html("Vuln Bank – History", "history", body)
    (outdir / "history.html").write_text(html, encoding="utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    findings = load_epss_findings(input_path)
    df = build_dataframe(findings)
    history_df = load_history(input_path)

    # Generate pages
    render_overview_page(df, findings, outdir)
    render_kev_page(df, outdir)
    render_packages_page(df, outdir)
    render_cvss_page(df, outdir)
    render_history_page(history_df, outdir)

    print(f"[INFO] Dashboard generated at: {outdir.resolve()}")


if __name__ == "__main__":
    main()
