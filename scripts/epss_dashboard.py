#!/usr/bin/env python3
"""
EPSS/KEV Dashboard generator for Vuln Bank

Reads:
  - security-reports/epss-findings.json  (from epss_gate.py)
  - security-reports/epss-history.jsonl  (append-only history)

Outputs:
  - site/index.html   (static dashboard for GitHub Pages)
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List
from string import Template
import html as html_lib


# -----------------------------
# Paths / constants
# -----------------------------
REPORT_DIR = Path("security-reports")
EPSS_FINDINGS_PATH = REPORT_DIR / "epss-findings.json"
EPSS_HISTORY_PATH = REPORT_DIR / "epss-history.jsonl"

SITE_DIR = Path("site")
OUTPUT_HTML = SITE_DIR / "index.html"


# -----------------------------
# Helpers
# -----------------------------
def load_epss_findings() -> Dict[str, Any]:
    """
    Load epss-findings.json produced by epss_gate.py.
    Returns a dict with safe defaults if missing/invalid.
    """
    if not EPSS_FINDINGS_PATH.exists():
        print(f"[WARN] EPSS findings not found: {EPSS_FINDINGS_PATH}")
        return {
            "threshold": None,
            "total_trivy_high_crit": 0,
            "high_risk": [],
            "_has_data": False,
        }

    try:
        with EPSS_FINDINGS_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
            data["_has_data"] = True
            return data
    except Exception as e:
        print(f"[WARN] Failed to read EPSS findings: {e}")
        return {
            "threshold": None,
            "total_trivy_high_crit": 0,
            "high_risk": [],
            "_has_data": False,
        }


def load_history() -> List[Dict[str, Any]]:
    """
    Load epss-history.jsonl as a list of records.
    Each line is a JSON object (written by epss_gate.py).
    """
    records: List[Dict[str, Any]] = []

    if not EPSS_HISTORY_PATH.exists():
        print(f"[INFO] No history file yet: {EPSS_HISTORY_PATH}")
        return records

    try:
        with EPSS_HISTORY_PATH.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    records.append(rec)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"[WARN] Failed to read history: {e}")

    # Sort by timestamp if present
    def _ts(rec: Dict[str, Any]) -> str:
        return rec.get("timestamp") or ""

    records.sort(key=_ts)
    return records


def format_percent(value: float) -> str:
    try:
        return f"{value * 100:.1f}%"
    except Exception:
        return "0.0%"


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def build_high_risk_table(high_risk: List[Dict[str, Any]]) -> str:
    """
    Build HTML rows for the high-risk vulnerabilities table.
    """
    if not high_risk:
        return (
            "<tr>"
            "<td colspan='9' class='empty'>No high-risk CVEs (EPSS/KEV) found – clean run.</td>"
            "</tr>"
        )

    # Ensure sorted by EPSS (desc)
    try:
        high_risk = sorted(high_risk, key=lambda x: safe_float(x.get("epss", 0.0)), reverse=True)
    except Exception:
        pass

    rows: List[str] = []
    for idx, item in enumerate(high_risk, start=1):
        cve = item.get("cve") or "-"
        pkg = item.get("pkg_name") or "-"
        installed = item.get("installed_version") or "-"
        fixed = item.get("fixed_version") or "N/A"
        severity = item.get("severity") or "-"
        epss = safe_float(item.get("epss", 0.0))
        percentile = safe_float(item.get("percentile", 0.0))
        is_kev = bool(item.get("is_kev", False))
        reasons = item.get("reasons") or []
        target = item.get("target") or "-"
        cvss = item.get("cvss")
        description = item.get("description") or ""

        desc_short = description
        if len(desc_short) > 180:
            desc_short = desc_short[:180] + "…"

        # Escape dangerous characters
        cve_html = html_lib.escape(cve)
        pkg_html = html_lib.escape(pkg)
        installed_html = html_lib.escape(installed)
        fixed_html = html_lib.escape(fixed)
        severity_html = html_lib.escape(severity)
        target_html = html_lib.escape(target)
        desc_html = html_lib.escape(desc_short)
        reasons_html = html_lib.escape(", ".join(reasons))

        cve_link = (
            f"https://nvd.nist.gov/vuln/detail/{cve_html}"
            if cve_html.startswith("CVE-")
            else "#"
        )

        cvss_display = f"{cvss:.1f}" if isinstance(cvss, (int, float)) else "-"

        kev_badge = (
            "<span class='badge kev'>KEV</span>" if is_kev else "<span class='badge neutral'>No</span>"
        )

        severity_class = "sev-high" if severity_html == "HIGH" else ""
        if severity_html == "CRITICAL":
            severity_class = "sev-critical"

        row = f"""
        <tr>
          <td>{idx}</td>
          <td class="mono">
            <a href="{cve_link}" target="_blank" rel="noopener noreferrer">{cve_html}</a>
          </td>
          <td><span class="badge {severity_class}">{severity_html}</span></td>
          <td>{format_percent(epss)}</td>
          <td>{format_percent(percentile)}</td>
          <td>{kev_badge}</td>
          <td class="mono">
            {pkg_html}<br/>
            <small>{installed_html} → {fixed_html}</small>
          </td>
          <td class="mono">{target_html}</td>
          <td>
            <div class="desc">{desc_html}</div>
            <small class="reasons">{reasons_html}</small>
          </td>
        </tr>
        """
        rows.append(row)
    return "\n".join(rows)


def build_history_chart_data(history: List[Dict[str, Any]]) -> Dict[str, Any]:
    labels: List[str] = []
    epss_hits: List[int] = []
    kev_hits: List[int] = []
    max_epss: List[float] = []

    for rec in history:
        ts = rec.get("timestamp") or ""
        # Pretty label (short)
        label = ts
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            label = dt.strftime("%Y-%m-%d %H:%M")
        except Exception:
            pass

        labels.append(label)
        epss_hits.append(safe_int(rec.get("epss_above_threshold", 0)))
        kev_hits.append(safe_int(rec.get("kev_count", rec.get("kev_hits", 0))))
        max_epss.append(safe_float(rec.get("max_epss", 0.0)))

    return {
        "labels": labels,
        "epss_above_threshold": epss_hits,
        "kev_hits": kev_hits,
        "max_epss": max_epss,
    }


def compute_summary(findings: Dict[str, Any], history: List[Dict[str, Any]]) -> Dict[str, Any]:
    high_risk = findings.get("high_risk") or []
    total_trivy = safe_int(findings.get("total_trivy_high_crit", 0))
    threshold = findings.get("threshold")

    kev_count = sum(1 for r in high_risk if r.get("is_kev"))
    max_epss = 0.0
    for r in high_risk:
        epss = safe_float(r.get("epss", 0.0))
        if epss > max_epss:
            max_epss = epss

    last_updated = None
    if history:
        last = history[-1]
        last_updated = last.get("timestamp")

    if last_updated:
        try:
            dt = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
            last_updated_str = dt.strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            last_updated_str = last_updated
    else:
        last_updated_str = "No runs yet"

    return {
        "total_trivy": total_trivy,
        "high_risk_count": len(high_risk),
        "kev_count": kev_count,
        "threshold": threshold,
        "max_epss": max_epss,
        "last_updated": last_updated_str,
    }


# -----------------------------
# HTML template (Chart.js)
# -----------------------------
HTML_TEMPLATE = Template(
    """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Vuln Bank – EPSS / KEV Risk Dashboard</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root {
      --bg: #050816;
      --bg-card: #0b1020;
      --bg-alt: #111827;
      --border-subtle: #1f2933;
      --accent: #3b82f6;
      --accent-soft: rgba(59, 130, 246, 0.15);
      --text-main: #e5e7eb;
      --text-muted: #9ca3af;
      --danger: #ef4444;
      --danger-soft: rgba(239, 68, 68, 0.1);
      --warning: #f97316;
      --kev: #facc15;
      --kev-soft: rgba(250, 204, 21, 0.18);
      --mono: "Fira Code", "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      --radius-xl: 18px;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif;
      background: radial-gradient(circle at top, #111827 0, #020617 45%, #020617 100%);
      color: var(--text-main);
      padding: 24px;
    }

    .layout {
      max-width: 1180px;
      margin: 0 auto 60px auto;
    }

    header {
      margin-bottom: 24px;
    }

    .title-row {
      display: flex;
      flex-wrap: wrap;
      align-items: baseline;
      gap: 8px 16px;
      justify-content: space-between;
    }

    h1 {
      font-size: 26px;
      font-weight: 650;
      letter-spacing: -0.03em;
      display: flex;
      align-items: center;
      gap: 10px;
    }

    h1 span.mark {
      font-size: 18px;
      padding: 3px 10px;
      border-radius: 999px;
      background: #111827;
      border: 1px solid var(--border-subtle);
      color: var(--text-muted);
    }

    .subtitle {
      font-size: 14px;
      color: var(--text-muted);
      margin-top: 4px;
    }

    .meta {
      font-size: 13px;
      color: var(--text-muted);
      text-align: right;
    }

    .meta span.val {
      color: var(--text-main);
      font-weight: 500;
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 16px;
      margin-top: 24px;
      margin-bottom: 24px;
    }

    .card {
      background: radial-gradient(circle at top left, #111827 0, #020617 55%);
      border-radius: var(--radius-xl);
      border: 1px solid var(--border-subtle);
      padding: 14px 16px 14px 16px;
      box-shadow: 0 18px 45px rgba(15, 23, 42, 0.75);
    }

    .card-muted {
      background: radial-gradient(circle at top left, #020617 0, #020617 60%);
      opacity: 0.92;
    }

    .card-title {
      font-size: 13px;
      color: var(--text-muted);
      margin-bottom: 6px;
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      gap: 8px;
    }

    .card-value {
      font-size: 22px;
      font-weight: 600;
    }

    .card-value.danger {
      color: var(--danger);
    }

    .card-value.ok {
      color: var(--accent);
    }

    .card-tag {
      font-size: 11px;
      padding: 2px 8px;
      border-radius: 999px;
      border: 1px solid var(--border-subtle);
      color: var(--text-muted);
    }

    .badge {
      display: inline-flex;
      align-items: center;
      padding: 2px 8px;
      font-size: 11px;
      border-radius: 999px;
      background: rgba(148, 163, 184, 0.15);
      border: 1px solid rgba(148, 163, 184, 0.4);
      color: #e5e7eb;
      white-space: nowrap;
    }

    .badge.kev {
      background: var(--kev-soft);
      border-color: rgba(250, 204, 21, 0.5);
      color: #facc15;
      font-weight: 600;
    }

    .badge.neutral {
      opacity: 0.7;
    }

    .badge.sev-high {
      background: rgba(249, 115, 22, 0.16);
      border-color: rgba(249, 115, 22, 0.7);
      color: #fed7aa;
    }

    .badge.sev-critical {
      background: var(--danger-soft);
      border-color: rgba(248, 113, 113, 0.7);
      color: #fecaca;
      font-weight: 600;
    }

    .chart-card {
      margin-top: 12px;
      padding: 16px 18px 18px 18px;
      background: radial-gradient(circle at top left, #020617 0, #020617 60%);
      border-radius: var(--radius-xl);
      border: 1px solid var(--border-subtle);
    }

    .chart-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
    }

    .chart-header h2 {
      font-size: 15px;
      font-weight: 500;
    }

    .chart-header small {
      font-size: 12px;
      color: var(--text-muted);
    }

    canvas {
      width: 100%;
      max-height: 260px;
    }

    .section {
      margin-top: 26px;
    }

    .section-header {
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      margin-bottom: 10px;
    }

    .section-header h2 {
      font-size: 16px;
      font-weight: 550;
    }

    .section-header small {
      font-size: 12px;
      color: var(--text-muted);
    }

    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 6px;
      background: #020617;
      border-radius: var(--radius-xl);
      overflow: hidden;
      border: 1px solid var(--border-subtle);
    }

    thead {
      background: rgba(15, 23, 42, 0.98);
    }

    th, td {
      padding: 8px 10px;
      font-size: 12px;
      vertical-align: top;
      border-bottom: 1px solid rgba(31, 41, 55, 0.75);
    }

    th {
      text-align: left;
      font-weight: 500;
      color: var(--text-muted);
      white-space: nowrap;
    }

    tbody tr:last-child td {
      border-bottom: none;
    }

    tbody tr:nth-child(even) {
      background: rgba(15, 23, 42, 0.6);
    }

    tbody tr:hover {
      background: rgba(15, 23, 42, 0.95);
    }

    td.mono, a {
      font-family: var(--mono);
    }

    td .desc {
      font-size: 12px;
      color: var(--text-main);
      margin-bottom: 4px;
    }

    td .reasons {
      font-size: 11px;
      color: var(--text-muted);
    }

    td.empty {
      text-align: center;
      font-size: 13px;
      padding: 18px;
      color: var(--text-muted);
    }

    a {
      color: var(--accent);
      text-decoration: none;
    }

    a:hover {
      text-decoration: underline;
    }

    footer {
      margin-top: 32px;
      font-size: 11px;
      color: var(--text-muted);
      text-align: right;
    }

    @media (max-width: 960px) {
      body {
        padding: 16px;
      }
      .grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }
    }

    @media (max-width: 720px) {
      .grid {
        grid-template-columns: 1fr;
      }
      .title-row {
        flex-direction: column;
        align-items: flex-start;
      }
      header {
        margin-bottom: 18px;
      }
    }
  </style>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
  <div class="layout">
    <header>
      <div class="title-row">
        <div>
          <h1>
            Vuln Bank
            <span class="mark">EPSS × KEV Dashboard</span>
          </h1>
          <div class="subtitle">
            Risk-aware view of <strong>Trivy SCA</strong> findings, prioritized with <strong>EPSS</strong> and
            <strong>CISA KEV</strong>.
          </div>
        </div>
        <div class="meta">
          <div>Last updated: <span class="val">$last_updated</span></div>
          <div>Data source: <span class="val">security-reports/epss-findings.json</span></div>
        </div>
      </div>

      <div class="grid">
        <div class="card">
          <div class="card-title">
            <span>Total HIGH/CRIT from Trivy</span>
            <span class="card-tag">Trivy FS</span>
          </div>
          <div class="card-value">$total_trivy</div>
        </div>
        <div class="card">
          <div class="card-title">
            <span>High-risk (EPSS / KEV)</span>
            <span class="card-tag">Gate scope</span>
          </div>
          <div class="card-value $risk_class">$high_risk_count</div>
        </div>
        <div class="card card-muted">
          <div class="card-title">
            <span>EPSS threshold · Max EPSS</span>
            <span class="card-tag">FIRST.org</span>
          </div>
          <div class="card-value">
            $threshold_display
            <span style="font-size:12px; color:var(--text-muted); margin-left:8px;">
              Max: $max_epss_pct
            </span>
          </div>
        </div>
      </div>
    </header>

    <section class="section">
      <div class="chart-card">
        <div class="chart-header">
          <h2>Gate history – EPSS/KEV across runs</h2>
          <small>Based on epss-history.jsonl</small>
        </div>
        <canvas id="historyChart"></canvas>
      </div>
    </section>

    <section class="section">
      <div class="section-header">
        <h2>High-risk CVEs (EPSS ≥ threshold or KEV)</h2>
        <small>$kev_count KEV entries · sorted by EPSS descending</small>
      </div>
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>CVE</th>
            <th>Severity</th>
            <th>EPSS</th>
            <th>Percentile</th>
            <th>KEV</th>
            <th>Package</th>
            <th>Target</th>
            <th>Description / Reasons</th>
          </tr>
        </thead>
        <tbody>
          $high_risk_table
        </tbody>
      </table>
    </section>

    <footer>
      Generated by <span class="val">scripts/epss_gate.py &amp; scripts/epss_dashboard.py</span>.
      EPSS © FIRST.org · KEV © CISA.
    </footer>
  </div>

  <script>
    const DASHBOARD_DATA = $chart_json;

    (function() {
      const ctx = document.getElementById('historyChart').getContext('2d');
      const labels = DASHBOARD_DATA.labels || [];
      const epHits = DASHBOARD_DATA.epss_above_threshold || [];
      const kevHits = DASHBOARD_DATA.kev_hits || [];
      const maxEpss = DASHBOARD_DATA.max_epss || [];

      if (labels.length === 0) {
        // no data, render a tiny "no data" message instead of chart
        const canvas = document.getElementById('historyChart');
        const parent = canvas.parentElement;
        parent.innerHTML = "<div style='font-size:12px; color:#9ca3af;'>No history data yet. Run the EPSS gate pipeline to populate epss-history.jsonl.</div>";
        return;
      }

      new Chart(ctx, {
        type: 'line',
        data: {
          labels: labels,
          datasets: [
            {
              label: 'EPSS≥threshold findings',
              data: epHits,
              borderColor: 'rgba(59, 130, 246, 1)',
              backgroundColor: 'rgba(59, 130, 246, 0.15)',
              borderWidth: 2,
              tension: 0.25,
              fill: true,
              yAxisID: 'y'
            },
            {
              label: 'KEV hits',
              data: kevHits,
              borderColor: 'rgba(250, 204, 21, 1)',
              backgroundColor: 'rgba(250, 204, 21, 0.18)',
              borderWidth: 2,
              tension: 0.25,
              fill: true,
              yAxisID: 'y'
            },
            {
              label: 'Max EPSS (0–1)',
              data: maxEpss,
              borderColor: 'rgba(248, 113, 113, 1)',
              backgroundColor: 'rgba(248, 113, 113, 0.15)',
              borderWidth: 2,
              tension: 0.25,
              fill: false,
              yAxisID: 'y1'
            }
          ]
        },
        options: {
          responsive: true,
          plugins: {
            legend: {
              labels: {
                color: '#e5e7eb',
                font: {
                  size: 11
                }
              }
            },
            tooltip: {
              backgroundColor: '#020617',
              borderColor: '#1f2933',
              borderWidth: 1,
              titleColor: '#e5e7eb',
              bodyColor: '#e5e7eb',
              padding: 8
            }
          },
          scales: {
            x: {
              ticks: {
                color: '#9ca3af',
                maxRotation: 55,
                minRotation: 35
              },
              grid: {
                color: 'rgba(31, 41, 55, 0.6)'
              }
            },
            y: {
              position: 'left',
              ticks: {
                color: '#9ca3af',
                precision: 0
              },
              grid: {
                color: 'rgba(31, 41, 55, 0.6)'
              }
            },
            y1: {
              position: 'right',
              ticks: {
                color: '#9ca3af'
              },
              grid: {
                drawOnChartArea: false
              },
              min: 0,
              max: 1
            }
          }
        }
      });
    })();
  </script>
</body>
</html>
"""
)


# -----------------------------
# Main
# -----------------------------
def main() -> None:
    SITE_DIR.mkdir(parents=True, exist_ok=True)

    findings = load_epss_findings()
    history = load_history()

    high_risk = findings.get("high_risk") or []
    chart_data = build_history_chart_data(history)
    summary = compute_summary(findings, history)

    # Summary-derived fields
    total_trivy = summary["total_trivy"]
    high_risk_count = summary["high_risk_count"]
    kev_count = summary["kev_count"]
    threshold = summary["threshold"]
    max_epss = summary["max_epss"]
    last_updated = summary["last_updated"]

    if threshold is None:
        threshold_display = "–"
    else:
        try:
            threshold_display = f"{float(threshold):.2f}"
        except Exception:
            threshold_display = str(threshold)

    max_epss_pct = format_percent(max_epss)
    risk_class = "danger" if high_risk_count > 0 else "ok"

    high_risk_table_html = build_high_risk_table(high_risk)
    chart_json_str = json.dumps(chart_data)

    html = HTML_TEMPLATE.substitute(
        last_updated=html_lib.escape(last_updated),
        total_trivy=total_trivy,
        high_risk_count=high_risk_count,
        kev_count=kev_count,
        threshold_display=threshold_display,
        max_epss_pct=max_epss_pct,
        risk_class=risk_class,
        high_risk_table=high_risk_table_html,
        chart_json=chart_json_str,
    )

    OUTPUT_HTML.write_text(html, encoding="utf-8")
    print(f"[INFO] EPSS dashboard generated at: {OUTPUT_HTML}")


if __name__ == "__main__":
    main()
