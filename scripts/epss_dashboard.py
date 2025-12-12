#!/usr/bin/env python3
"""
Vuln Bank - Risk-Aware EPSS/KEV Dashboard (Static HTML)

Features:
- Page: index.html (KPI + Auto Explanation)
- Page: remediation.html (Remediation Plan + SLA + grouped by package)
- Page: risks.html (Raw high-risk table)
- Outputs: site/ + remediation.json (machine-readable)

Works even when:
- high_risk is empty
- history file missing
- some fields missing (cvss, fixed_version, reasons, etc.)

Usage:
  python scripts/epss_dashboard.py --input security-reports/epss-findings.json --outdir site
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import math


# ---------------------------
# CLI
# ---------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True, help="Path to epss-findings.json")
    p.add_argument("--outdir", required=True, help="Output directory, e.g. site/")
    return p.parse_args()


# ---------------------------
# Data models
# ---------------------------
@dataclass
class Finding:
    cve: str
    pkg_name: str
    severity: str
    epss: float
    percentile: float
    is_kev: bool
    cvss: Optional[float]
    installed_version: Optional[str]
    fixed_version: Optional[str]
    target: Optional[str]
    reasons: List[str]
    description: Optional[str]
    priority_score: float

    def sev_weight(self) -> float:
        s = (self.severity or "").upper()
        if s == "CRITICAL":
            return 1.0
        if s == "HIGH":
            return 0.7
        return 0.4


# ---------------------------
# Utils
# ---------------------------
def now_utc_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def safe_float(v: Any, default: float = 0.0) -> float:
    try:
        if v is None:
            return default
        return float(v)
    except (ValueError, TypeError):
        return default


def safe_str(v: Any, default: str = "") -> str:
    if v is None:
        return default
    return str(v)


def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def compute_priority_score(
    epss: float,
    cvss: Optional[float],
    is_kev: bool,
    severity: str,
) -> float:
    """
    Priority model (0..100-ish), engineered for triage:
    - EPSS dominates (prob exploit)
    - CVSS adds technical impact
    - KEV is a strong override
    - Severity bumps CRITICAL
    """
    epss_part = clamp(epss, 0.0, 1.0) * 60.0  # 0..60
    cvss_part = clamp(safe_float(cvss, 0.0), 0.0, 10.0) * 3.0  # 0..30
    kev_part = 20.0 if is_kev else 0.0  # 0 or 20
    sev_part = 10.0 if (severity or "").upper() == "CRITICAL" else 0.0  # +10
    score = epss_part + cvss_part + kev_part + sev_part
    return round(score, 2)


def sla_from_score(score: float, is_kev: bool, severity: str) -> Tuple[str, str]:
    """
    Returns (SLA, urgency_label)
    """
    sev = (severity or "").upper()
    if is_kev or score >= 85:
        return ("24h", "P0 - Immediate")
    if sev == "CRITICAL" or score >= 70:
        return ("48h", "P1 - High")
    if score >= 50:
        return ("7d", "P2 - Medium")
    return ("30d", "P3 - Low")


def remediation_action(f: Finding) -> str:
    """
    Action recommendation with minimal assumptions.
    """
    fix = (f.fixed_version or "").strip()
    inst = (f.installed_version or "").strip()

    if fix and fix.upper() != "N/A":
        if inst:
            return f"Upgrade `{f.pkg_name}` from `{inst}` → `{fix}`"
        return f"Upgrade `{f.pkg_name}` → `{fix}`"

    # No fixed version known
    if f.pkg_name:
        return (
            f"Mitigate `{f.pkg_name}`: "
            "pin patched release when available; "
            "apply compensating controls (WAF rules, disable vulnerable feature, tighten config)."
        )
    return "Mitigate: apply compensating controls; monitor for vendor patch."


def reason_summary(f: Finding, threshold: float) -> str:
    r = []
    if f.is_kev:
        r.append("CISA KEV")
    if f.epss >= threshold:
        r.append(f"EPSS≥{threshold}")
    if f.cvss is not None and safe_float(f.cvss, 0.0) >= 9.0:
        r.append("CVSS≥9.0")
    if (f.severity or "").upper() == "CRITICAL":
        r.append("CRITICAL severity")
    if f.reasons:
        # keep original reasons too (but avoid duplicates)
        for x in f.reasons:
            if x not in r:
                r.append(x)
    return ", ".join(r) if r else "Risk signals detected"


# ---------------------------
# Loaders
# ---------------------------
def load_epss_findings(path: Path) -> Tuple[float, int, List[Finding]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    threshold = safe_float(data.get("threshold"), 0.5)
    total_high_crit = int(safe_float(data.get("total_trivy_high_crit"), 0))

    rows = data.get("high_risk") or []
    findings: List[Finding] = []

    for r in rows:
        cve = safe_str(r.get("cve"), "UNKNOWN")
        pkg = safe_str(r.get("pkg_name"), "unknown-package")
        sev = safe_str(r.get("severity"), "HIGH").upper()
        epss = safe_float(r.get("epss"), 0.0)
        percentile = safe_float(r.get("percentile"), 0.0)
        is_kev = bool(r.get("is_kev", False))
        cvss = r.get("cvss")
        cvss_f = None if cvss is None else safe_float(cvss, None)  # allow None

        installed = r.get("installed_version")
        fixed = r.get("fixed_version")
        target = r.get("target")
        reasons = r.get("reasons") or []
        desc = r.get("description")

        # priority_score: prefer existing, else compute
        ps = r.get("priority_score")
        if ps is None:
            ps_val = compute_priority_score(epss, cvss_f, is_kev, sev)
        else:
            ps_val = safe_float(ps, 0.0)

        findings.append(
            Finding(
                cve=cve,
                pkg_name=pkg,
                severity=sev,
                epss=epss,
                percentile=percentile,
                is_kev=is_kev,
                cvss=cvss_f,
                installed_version=safe_str(installed, "") if installed is not None else None,
                fixed_version=safe_str(fixed, "") if fixed is not None else None,
                target=safe_str(target, "") if target is not None else None,
                reasons=[safe_str(x) for x in reasons if x is not None],
                description=safe_str(desc, "") if desc is not None else None,
                priority_score=ps_val,
            )
        )

    # sort by priority_score desc, then epss desc
    findings.sort(key=lambda x: (x.priority_score, x.epss), reverse=True)
    return threshold, total_high_crit, findings


# ---------------------------
# Auto Explanation (Step 4)
# ---------------------------
def build_auto_explanation(findings: List[Finding], threshold: float) -> Dict[str, Any]:
    """
    Returns structured explanation + suggested narrative for index page.
    """
    if not findings:
        return {
            "status": "PASS",
            "headline": "0 High-Risk Vulnerabilities",
            "summary": "EPSS and CISA KEV prioritization passed successfully.",
            "bullets": [
                "No vulnerabilities met KEV or EPSS threshold criteria.",
                "Continue monitoring daily and keep dependencies updated.",
            ],
            "top_drivers": [],
        }

    top = findings[:5]
    drivers = []
    for f in top:
        drivers.append(
            {
                "cve": f.cve,
                "package": f.pkg_name,
                "severity": f.severity,
                "epss": f.epss,
                "cvss": f.cvss,
                "is_kev": f.is_kev,
                "priority_score": f.priority_score,
                "reason": reason_summary(f, threshold),
            }
        )

    kev_count = sum(1 for f in findings if f.is_kev)
    epss_count = sum(1 for f in findings if f.epss >= threshold)
    critical_count = sum(1 for f in findings if (f.severity or "").upper() == "CRITICAL")
    max_score = max((f.priority_score for f in findings), default=0.0)

    bullets = [
        f"High-risk findings detected: {len(findings)}",
        f"CISA KEV matches: {kev_count}",
        f"EPSS ≥ {threshold}: {epss_count}",
        f"CRITICAL severity: {critical_count}",
        f"Max priority score: {max_score}",
    ]

    return {
        "status": "FAIL",
        "headline": f"{len(findings)} High-Risk Vulnerabilities",
        "summary": "At least one vulnerability met prioritization criteria (CISA KEV and/or EPSS threshold).",
        "bullets": bullets,
        "top_drivers": drivers,
    }


# ---------------------------
# Remediation Plan (Step 5)
# ---------------------------
def build_remediation_plan(findings: List[Finding], threshold: float) -> Dict[str, Any]:
    """
    Produces a remediation plan:
    - items sorted by priority_score
    - grouping by package
    - SLA + suggested action
    """
    items = []
    by_package: Dict[str, Dict[str, Any]] = {}

    for f in findings:
        sla, urgency = sla_from_score(f.priority_score, f.is_kev, f.severity)
        action = remediation_action(f)
        why = reason_summary(f, threshold)

        item = {
            "cve": f.cve,
            "pkg_name": f.pkg_name,
            "severity": f.severity,
            "epss": f.epss,
            "percentile": f.percentile,
            "cvss": f.cvss,
            "is_kev": f.is_kev,
            "priority_score": f.priority_score,
            "sla": sla,
            "urgency": urgency,
            "action": action,
            "why": why,
            "installed_version": f.installed_version,
            "fixed_version": f.fixed_version,
            "target": f.target,
        }
        items.append(item)

        pkg = f.pkg_name
        if pkg not in by_package:
            by_package[pkg] = {
                "pkg_name": pkg,
                "count": 0,
                "max_priority_score": 0.0,
                "kev_hits": 0,
                "top_cves": [],
            }

        by_package[pkg]["count"] += 1
        by_package[pkg]["max_priority_score"] = max(by_package[pkg]["max_priority_score"], f.priority_score)
        if f.is_kev:
            by_package[pkg]["kev_hits"] += 1
        if len(by_package[pkg]["top_cves"]) < 5:
            by_package[pkg]["top_cves"].append(f.cve)

    # Sort package groups
    pkg_groups = sorted(by_package.values(), key=lambda x: x["max_priority_score"], reverse=True)
    # Sort items (already sorted but keep deterministic)
    items.sort(key=lambda x: x["priority_score"], reverse=True)

    return {
        "generated_at": now_utc_iso(),
        "summary": {
            "total_high_risk": len(findings),
            "packages_affected": len(pkg_groups),
            "top_priority_score": items[0]["priority_score"] if items else 0.0,
        },
        "items": items,
        "packages": pkg_groups,
    }


# ---------------------------
# HTML rendering (no templates required)
# ---------------------------
def html_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def render_base(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>{html_escape(title)}</title>
  <style>
    :root {{
      --bg: #0b1220;
      --card: #0f1a2e;
      --muted: rgba(255,255,255,.72);
      --text: rgba(255,255,255,.92);
      --border: rgba(255,255,255,.10);
      --green: #1db954;
      --red: #ff4d4d;
      --amber: #ffb020;
      --blue: #4aa3ff;
    }}
    body {{
      margin: 0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
      background: radial-gradient(1200px 700px at 20% 10%, rgba(74,163,255,.18), transparent 60%),
                  radial-gradient(1000px 600px at 70% 30%, rgba(29,185,84,.16), transparent 60%),
                  var(--bg);
      color: var(--text);
    }}
    .wrap {{ max-width: 1080px; margin: 0 auto; padding: 32px 18px; }}
    .nav {{
      display:flex; gap:14px; align-items:center; flex-wrap:wrap;
      margin-bottom: 18px;
    }}
    .nav a {{
      color: var(--text);
      text-decoration: none;
      padding: 8px 12px;
      border: 1px solid var(--border);
      border-radius: 10px;
      background: rgba(255,255,255,.03);
    }}
    .nav a:hover {{ border-color: rgba(255,255,255,.22); }}
    .grid {{ display:grid; grid-template-columns: repeat(12, 1fr); gap: 14px; }}
    .card {{
      grid-column: span 12;
      background: rgba(255,255,255,.03);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 18px;
      box-shadow: 0 10px 30px rgba(0,0,0,.25);
    }}
    .kpi {{
      display:flex; gap:14px; align-items:center;
      padding: 22px;
      border-radius: 22px;
      border: 1px solid rgba(255,255,255,.12);
      background: linear-gradient(135deg, rgba(29,185,84,.9), rgba(29,185,84,.55));
    }}
    .kpi.fail {{
      background: linear-gradient(135deg, rgba(255,77,77,.95), rgba(255,77,77,.55));
    }}
    .kpi .big {{ font-size: 44px; font-weight: 800; letter-spacing: -.02em; }}
    .kpi .sub {{ margin-top: 6px; font-size: 16px; color: rgba(255,255,255,.92); }}
    .pill {{
      display:inline-block; padding: 4px 10px; border-radius: 999px;
      border:1px solid var(--border); background: rgba(0,0,0,.22);
      font-size: 12px; color: rgba(255,255,255,.86);
    }}
    table {{ width:100%; border-collapse: collapse; overflow:hidden; border-radius: 14px; }}
    th, td {{ padding: 10px 10px; border-bottom: 1px solid var(--border); text-align:left; font-size: 14px; }}
    th {{ color: rgba(255,255,255,.86); font-weight: 700; background: rgba(255,255,255,.04); }}
    .sev-critical {{ color: #ffd1d1; }}
    .sev-high {{ color: #ffe5b4; }}
    .muted {{ color: var(--muted); }}
    .footer {{ margin-top: 20px; color: rgba(255,255,255,.55); font-size: 12px; text-align:center; }}
    .two {{ grid-column: span 12; }}
    @media (min-width: 900px) {{
      .two {{ grid-column: span 6; }}
    }}
    .list li {{ margin: 6px 0; }}
    .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="nav">
      <a href="./index.html">Overview</a>
      <a href="./risks.html">Risks</a>
      <a href="./remediation.html">Remediation</a>
    </div>
    {body}
    <div class="footer">Vuln Bank · Risk-Aware DevSecOps Dashboard</div>
  </div>
</body>
</html>
"""


def render_index(expl: Dict[str, Any], threshold: float, generated_at: str) -> str:
    status = expl["status"]
    headline = expl["headline"]
    summary = expl["summary"]
    bullets = expl.get("bullets", [])
    top = expl.get("top_drivers", [])

    kpi_class = "kpi" if status == "PASS" else "kpi fail"
    badge = "✅ PASS" if status == "PASS" else "🚨 ACTION REQUIRED"

    top_rows = ""
    if top:
        for t in top:
            sev = html_escape(t["severity"])
            sev_cls = "sev-critical" if sev == "CRITICAL" else "sev-high"
            top_rows += f"""
              <tr>
                <td class="mono">{html_escape(t["cve"])}</td>
                <td>{html_escape(t["package"])}</td>
                <td class="{sev_cls}">{sev}</td>
                <td>{t["epss"]:.4f}</td>
                <td>{"" if t["cvss"] is None else f"{t['cvss']:.1f}"}</td>
                <td>{t["priority_score"]:.2f}</td>
                <td>{html_escape(t["reason"])}</td>
              </tr>
            """

    top_table = ""
    if top_rows:
        top_table = f"""
        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <h3 style="margin:0;">Top Drivers</h3>
            <span class="pill">Why the gate would fail</span>
          </div>
          <div class="muted" style="margin:8px 0 12px 0;">Highest priority items influencing decision.</div>
          <table>
            <thead>
              <tr>
                <th>CVE</th><th>Package</th><th>Severity</th><th>EPSS</th><th>CVSS</th><th>Priority</th><th>Signals</th>
              </tr>
            </thead>
            <tbody>
              {top_rows}
            </tbody>
          </table>
        </div>
        """

    bullet_html = "".join([f"<li>{html_escape(str(b))}</li>" for b in bullets])

    body = f"""
    <div class="{kpi_class}">
      <div style="flex:1;">
        <div class="pill">{badge}</div>
        <div class="big" style="margin-top:10px;">{html_escape(headline)}</div>
        <div class="sub">{html_escape(summary)}</div>
        <div class="sub muted" style="margin-top:12px;">
          EPSS Threshold: <b>{threshold}</b><br/>
          Generated: <b>{html_escape(generated_at)}</b>
        </div>
      </div>
    </div>

    <div class="grid" style="margin-top:14px;">
      <div class="card two">
        <h3 style="margin:0;">Auto Explanation</h3>
        <div class="muted" style="margin-top:8px;">Human-readable decision trace.</div>
        <ul class="list" style="margin-top:10px;">
          {bullet_html if bullet_html else "<li>No additional signals.</li>"}
        </ul>
      </div>

      <div class="card two">
        <h3 style="margin:0;">Next Actions</h3>
        <div class="muted" style="margin-top:8px;">What to do immediately.</div>
        <ul class="list" style="margin-top:10px;">
          <li>Open <b>Remediation</b> page and assign owners + SLA.</li>
          <li>Patch packages with available fixed versions first.</li>
          <li>For no-fix CVEs: apply compensating controls and monitor.</li>
        </ul>
      </div>

      {top_table}
    </div>
    """
    return render_base("EPSS/KEV Overview", body)


def render_risks_page(findings: List[Finding], threshold: float) -> str:
    if not findings:
        body = """
        <div class="card">
          <h2 style="margin:0;">Risks</h2>
          <p class="muted">No high-risk findings. Nothing to remediate.</p>
        </div>
        """
        return render_base("Risks", body)

    rows = ""
    for f in findings:
        sev = (f.severity or "").upper()
        sev_cls = "sev-critical" if sev == "CRITICAL" else "sev-high"
        rows += f"""
          <tr>
            <td class="mono">{html_escape(f.cve)}</td>
            <td>{html_escape(f.pkg_name)}</td>
            <td class="{sev_cls}">{html_escape(sev)}</td>
            <td>{f.epss:.4f}</td>
            <td>{html_escape(f"{f.percentile:.2f}")}</td>
            <td>{"" if f.cvss is None else f"{f.cvss:.1f}"}</td>
            <td>{f.priority_score:.2f}</td>
            <td>{html_escape(reason_summary(f, threshold))}</td>
          </tr>
        """

    body = f"""
    <div class="card">
      <h2 style="margin:0;">Risks</h2>
      <p class="muted">High-risk vulnerabilities after EPSS/KEV prioritization.</p>
      <table>
        <thead>
          <tr>
            <th>CVE</th><th>Package</th><th>Severity</th><th>EPSS</th><th>Percentile</th><th>CVSS</th><th>Priority</th><th>Signals</th>
          </tr>
        </thead>
        <tbody>
          {rows}
        </tbody>
      </table>
    </div>
    """
    return render_base("Risks", body)


def render_remediation_page(plan: Dict[str, Any]) -> str:
    items = plan.get("items", [])
    pkgs = plan.get("packages", [])
    summary = plan.get("summary", {})

    if not items:
        body = f"""
        <div class="card">
          <h2 style="margin:0;">Remediation Plan</h2>
          <p class="muted">No high-risk findings. Remediation plan is empty.</p>
          <div class="pill">Packages affected: 0</div>
        </div>
        """
        return render_base("Remediation", body)

    # Summary cards
    body = f"""
    <div class="grid">
      <div class="card two">
        <h3 style="margin:0;">Plan Summary</h3>
        <ul class="list" style="margin-top:10px;">
          <li>Total high-risk: <b>{summary.get("total_high_risk", 0)}</b></li>
          <li>Packages affected: <b>{summary.get("packages_affected", 0)}</b></li>
          <li>Top priority score: <b>{summary.get("top_priority_score", 0)}</b></li>
        </ul>
      </div>
      <div class="card two">
        <h3 style="margin:0;">Operational Notes</h3>
        <ul class="list" style="margin-top:10px;">
          <li>Start from <b>P0/P1</b> items (KEV and high priority_score).</li>
          <li>Prefer fixes with known <b>fixed_version</b>.</li>
          <li>Group by package to reduce churn and PR count.</li>
        </ul>
      </div>
    </div>
    """

    # Package grouping table
    pkg_rows = ""
    for p in pkgs:
        pkg_rows += f"""
          <tr>
            <td>{html_escape(p["pkg_name"])}</td>
            <td>{p["count"]}</td>
            <td>{p["kev_hits"]}</td>
            <td>{p["max_priority_score"]:.2f}</td>
            <td class="mono">{html_escape(", ".join(p.get("top_cves", [])))}</td>
          </tr>
        """

    body += f"""
    <div class="card" style="margin-top:14px;">
      <h3 style="margin:0;">Grouping by Package</h3>
      <p class="muted">Use this view to plan upgrades and create batched PRs.</p>
      <table>
        <thead>
          <tr>
            <th>Package</th><th>Count</th><th>KEV Hits</th><th>Max Priority</th><th>Top CVEs</th>
          </tr>
        </thead>
        <tbody>
          {pkg_rows}
        </tbody>
      </table>
    </div>
    """

    # Remediation items table
    item_rows = ""
    for it in items[:200]:  # cap to keep page fast
        sev = (it.get("severity") or "").upper()
        sev_cls = "sev-critical" if sev == "CRITICAL" else "sev-high"
        item_rows += f"""
          <tr>
            <td class="mono">{html_escape(it.get("cve",""))}</td>
            <td>{html_escape(it.get("pkg_name",""))}</td>
            <td class="{sev_cls}">{html_escape(sev)}</td>
            <td>{safe_float(it.get("epss"),0):.4f}</td>
            <td>{"" if it.get("cvss") is None else f"{safe_float(it.get('cvss'),0):.1f}"}</td>
            <td>{safe_float(it.get("priority_score"),0):.2f}</td>
            <td>{html_escape(it.get("urgency",""))}</td>
            <td>{html_escape(it.get("sla",""))}</td>
            <td>{html_escape(it.get("action",""))}</td>
          </tr>
        """

    body += f"""
    <div class="card" style="margin-top:14px;">
      <h3 style="margin:0;">Remediation Items (Top Priority)</h3>
      <p class="muted">Sorted by priority_score descending.</p>
      <table>
        <thead>
          <tr>
            <th>CVE</th><th>Package</th><th>Severity</th><th>EPSS</th><th>CVSS</th>
            <th>Priority</th><th>Urgency</th><th>SLA</th><th>Action</th>
          </tr>
        </thead>
        <tbody>
          {item_rows}
        </tbody>
      </table>
      <p class="muted" style="margin-top:10px;">Export available as <span class="mono">remediation.json</span>.</p>
    </div>
    """
    return render_base("Remediation", body)


# ---------------------------
# Main
# ---------------------------
def main() -> None:
    args = parse_args()
    in_path = Path(args.input)
    outdir = Path(args.outdir)

    if not in_path.exists():
        raise SystemExit(f"[ERROR] Input not found: {in_path}")

    outdir.mkdir(parents=True, exist_ok=True)

    threshold, total_high_crit, findings = load_epss_findings(in_path)

    generated = now_utc_iso()

    # Step 4: Auto explanation
    expl = build_auto_explanation(findings, threshold)

    # Step 5: Remediation plan
    plan = build_remediation_plan(findings, threshold)

    # Write JSON plan
    (outdir / "remediation.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")

    # Render pages
    (outdir / "index.html").write_text(render_index(expl, threshold, generated), encoding="utf-8")
    (outdir / "risks.html").write_text(render_risks_page(findings, threshold), encoding="utf-8")
    (outdir / "remediation.html").write_text(render_remediation_page(plan), encoding="utf-8")

    print(f"[OK] Dashboard generated: {outdir}/index.html")
    print(f"[OK] Remediation JSON: {outdir}/remediation.json")
    print(f"[INFO] total_trivy_high_crit={total_high_crit} high_risk={len(findings)} threshold={threshold}")


if __name__ == "__main__":
    main()
