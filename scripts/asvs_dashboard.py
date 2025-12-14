#!/usr/bin/env python3
"""
ASVS Dashboard Generator (Static HTML for GitHub Pages)

Inputs:
  --scorecard docs/data/security-scorecard.json
  --asvs      (optional) security-reports/governance/asvs-coverage.json OR docs/data/governance/asvs-coverage.json
Outputs:
  --outdir    docs/dashboards/asvs  (writes index.html)

Design goals:
- Executive-grade visuals (no external JS/CSS deps)
- Works even if ASVS JSON is in "old exporter" shape
"""

from __future__ import annotations
import argparse
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple, Optional


def read_json(path: Path) -> Dict[str, Any]:
    if not path or not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_get(d: Dict[str, Any], keys: List[str], default=None):
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def normalize_asvs(asvs_raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Support two shapes:
    1) New schema shape:
       { meta, summary:{total,passed,failed,coverage_percent}, controls:[{id,level,status,evidence}] }
    2) Old exporter shape (your current asvs_export.py):
       { summary:{total_signals,unique_controls}, counts:{control:count}, delta:{...} }
    We normalize into:
      { meta, summary, controls, extras }
    """
    if not asvs_raw:
        return {"meta": {}, "summary": {}, "controls": [], "extras": {"note": "ASVS data not provided"}}

    # New schema?
    if "controls" in asvs_raw and isinstance(asvs_raw.get("controls"), list):
        meta = asvs_raw.get("meta") or {}
        summary = asvs_raw.get("summary") or {}
        controls = asvs_raw.get("controls") or []
        return {"meta": meta, "summary": summary, "controls": controls, "extras": {}}

    # Old schema fallback
    counts = asvs_raw.get("counts") or {}
    delta = asvs_raw.get("delta") or {}
    unique_controls = safe_get(asvs_raw, ["summary", "unique_controls"], 0) or 0
    total_signals = safe_get(asvs_raw, ["summary", "total_signals"], 0) or 0

    # Build pseudo-controls: status is NOT_APPLICABLE (unknown) and evidence = ["signal_count: X"]
    controls = []
    for cid, c in sorted(counts.items(), key=lambda x: str(x[0])):
        controls.append({
            "id": str(cid),
            "level": 1,
            "status": "NOT_APPLICABLE",
            "evidence": [f"signal_count: {c}"]
        })

    summary = {
        "total": int(unique_controls),
        "passed": 0,
        "failed": 0,
        "coverage_percent": 0
    }
    meta = {"asvs_version": "unknown", "generated_at": iso_now()}

    return {
        "meta": meta,
        "summary": summary,
        "controls": controls,
        "extras": {
            "legacy": True,
            "total_signals": int(total_signals),
            "unique_controls": int(unique_controls),
            "delta": delta
        }
    }


def grade_badge(grade: str) -> str:
    g = (grade or "").upper().strip()
    if g not in ("A", "B", "C", "D", "F"):
        g = "N/A"
    return g


def html_escape(s: Any) -> str:
    t = "" if s is None else str(s)
    return (t.replace("&", "&amp;")
              .replace("<", "&lt;")
              .replace(">", "&gt;")
              .replace('"', "&quot;")
              .replace("'", "&#39;"))


def top_controls(controls: List[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
    """
    Prefer FAIL first, then PASS, then NOT_APPLICABLE.
    """
    priority = {"FAIL": 0, "PASS": 1, "NOT_APPLICABLE": 2}
    def keyfn(x):
        st = (x.get("status") or "NOT_APPLICABLE").upper()
        return (priority.get(st, 3), str(x.get("id") or ""))
    return sorted(controls, key=keyfn)[:limit]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scorecard", required=True, help="Path to docs/data/security-scorecard.json")
    ap.add_argument("--asvs", default="", help="Path to ASVS coverage JSON (optional)")
    ap.add_argument("--outdir", required=True, help="Output directory (docs/dashboards/asvs)")
    args = ap.parse_args()

    scorecard_path = Path(args.scorecard)
    asvs_path = Path(args.asvs) if args.asvs else None
    outdir = Path(args.outdir)

    scorecard = read_json(scorecard_path)
    asvs_raw = read_json(asvs_path) if asvs_path else {}
    asvs = normalize_asvs(asvs_raw)

    repo = safe_get(scorecard, ["meta", "repo"], "unknown")
    generated_at = safe_get(scorecard, ["meta", "generated_at"], iso_now())
    version = safe_get(scorecard, ["meta", "version"], "unknown")

    maturity = safe_get(scorecard, ["score", "overall"], None)
    grade = grade_badge(safe_get(scorecard, ["score", "grade"], "N/A"))
    comp_owasp = safe_get(scorecard, ["score", "components", "owasp"], 0)
    comp_epss = safe_get(scorecard, ["score", "components", "epss"], 0)
    comp_sla = safe_get(scorecard, ["score", "components", "sla"], 0)

    epss_high = safe_get(scorecard, ["epss", "high_risk_count"], 0)
    epss_thr = safe_get(scorecard, ["epss", "threshold"], None)
    top_cves = safe_get(scorecard, ["epss", "top_cves"], []) or []

    sla_breaches = safe_get(scorecard, ["sla", "breaches_by_severity"], {}) or {}
    assets = safe_get(scorecard, ["assets"], []) or []

    # ASVS summary (new schema)
    asvs_total = safe_get(asvs, ["summary", "total"], 0)
    asvs_passed = safe_get(asvs, ["summary", "passed"], 0)
    asvs_failed = safe_get(asvs, ["summary", "failed"], 0)
    asvs_cov = safe_get(asvs, ["summary", "coverage_percent"], 0)

    # If legacy, show legacy stats
    legacy_note = ""
    if safe_get(asvs, ["extras", "legacy"], False):
        legacy_note = f"Legacy ASVS signals detected: total_signals={safe_get(asvs, ['extras','total_signals'], 0)}, unique_controls={safe_get(asvs, ['extras','unique_controls'], 0)}"

    controls = asvs.get("controls") or []
    top10 = top_controls(controls, limit=10)

    def kpi(val: Any, suffix: str = "") -> str:
        if val is None:
            return "N/A"
        return f"{val}{suffix}"

    # Inline CSS (Pages-friendly, no deps)
    css = """
    :root{
      --bg:#0b1220; --panel:#0f1a2e; --muted:#93a4c7; --text:#e7eefc;
      --ok:#3ddc97; --warn:#ffd36e; --bad:#ff6b6b; --info:#6ea8ff;
      --line: rgba(255,255,255,0.08);
      --shadow: 0 12px 30px rgba(0,0,0,0.35);
      --radius: 18px;
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      --sans: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, "Apple Color Emoji","Segoe UI Emoji";
    }
    body{ margin:0; font-family:var(--sans); background: radial-gradient(1200px 700px at 10% 10%, #16244a 0%, var(--bg) 55%), var(--bg); color:var(--text); }
    .wrap{ max-width:1200px; margin:0 auto; padding:28px 18px 48px; }
    .topbar{ display:flex; gap:16px; align-items:flex-start; justify-content:space-between; flex-wrap:wrap; }
    .title h1{ margin:0; font-size:28px; letter-spacing:0.2px; }
    .title .meta{ margin-top:6px; color:var(--muted); font-size:13px; }
    .badge{ display:inline-flex; align-items:center; gap:8px; padding:8px 12px; border:1px solid var(--line); border-radius:999px; background: rgba(255,255,255,0.04); }
    .badge b{ font-family:var(--mono); font-size:13px; }
    .grid{ margin-top:18px; display:grid; grid-template-columns: repeat(12, 1fr); gap:14px; }
    .card{ grid-column: span 12; background: rgba(255,255,255,0.04); border:1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); overflow:hidden; }
    .card .hd{ padding:14px 16px; border-bottom:1px solid var(--line); display:flex; justify-content:space-between; align-items:center; gap:10px; }
    .card .hd h2{ margin:0; font-size:14px; letter-spacing:0.4px; text-transform:uppercase; color: #cfe0ff; }
    .card .bd{ padding:14px 16px; }
    .kpis{ display:grid; grid-template-columns: repeat(12, 1fr); gap:12px; }
    .kpi{ grid-column: span 12; padding:14px; border-radius: 16px; border:1px solid var(--line); background: rgba(15,26,46,0.75); }
    .kpi .label{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:0.5px; }
    .kpi .value{ margin-top:8px; font-size:28px; font-weight:700; }
    .kpi .sub{ margin-top:6px; color:var(--muted); font-size:12px; }
    .row{ display:flex; gap:12px; flex-wrap:wrap; }
    .pill{ font-family:var(--mono); font-size:12px; color:#cfe0ff; border:1px solid var(--line); background: rgba(255,255,255,0.03); border-radius: 999px; padding:6px 10px; }
    table{ width:100%; border-collapse:collapse; }
    th, td{ text-align:left; padding:10px 8px; border-bottom:1px solid var(--line); font-size:13px; }
    th{ color:#cfe0ff; font-size:12px; text-transform:uppercase; letter-spacing:0.4px; }
    .status{ font-family:var(--mono); font-size:12px; padding:3px 8px; border-radius:999px; border:1px solid var(--line); display:inline-block; }
    .PASS{ color:var(--ok); background: rgba(61,220,151,0.08); }
    .FAIL{ color:var(--bad); background: rgba(255,107,107,0.08); }
    .NOT_APPLICABLE{ color:var(--warn); background: rgba(255,211,110,0.08); }
    .small{ color:var(--muted); font-size:12px; line-height:1.55; }
    .col6{ grid-column: span 12; }
    @media (min-width: 920px){
      .col6{ grid-column: span 6; }
      .kpi{ grid-column: span 3; }
    }
    .bar{ height:10px; background: rgba(255,255,255,0.08); border-radius:999px; overflow:hidden; border:1px solid var(--line); }
    .bar > i{ display:block; height:100%; width:0%; background: linear-gradient(90deg, var(--info), var(--ok)); }
    .foot{ margin-top:18px; color:var(--muted); font-size:12px; }
    a{ color:#9dc0ff; text-decoration:none; }
    a:hover{ text-decoration:underline; }
    """

    def pct(x: Any) -> int:
        try:
            v = int(round(float(x)))
            return max(0, min(100, v))
        except Exception:
            return 0

    maturity_pct = pct(maturity)
    owasp_pct = pct(comp_owasp)
    epss_pct = pct(comp_epss)
    sla_pct = pct(comp_sla)
    asvs_pct = pct(asvs_cov)

    # HTML building
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Vuln Bank — Security Dashboard</title>
  <style>{css}</style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="title">
        <h1>Vuln Bank — Security Dashboard</h1>
        <div class="meta">
          Repo: <b>{html_escape(repo)}</b> · Version: <b>{html_escape(version)}</b><br/>
          Generated: <b>{html_escape(generated_at)}</b>
        </div>
      </div>
      <div class="badge">
        <span>Security Grade</span>
        <b>{html_escape(grade)}</b>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <div class="hd">
          <h2>Management KPIs</h2>
          <div class="row">
            <span class="pill">Maturity: {maturity_pct}/100</span>
            <span class="pill">OWASP: {owasp_pct}</span>
            <span class="pill">EPSS: {epss_pct}</span>
            <span class="pill">SLA: {sla_pct}</span>
          </div>
        </div>
        <div class="bd">
          <div class="kpis">
            <div class="kpi">
              <div class="label">Security Maturity</div>
              <div class="value">{kpi(maturity_pct, "/100")}</div>
              <div class="bar"><i style="width:{maturity_pct}%"></i></div>
              <div class="sub">Composite score: OWASP + EPSS + SLA</div>
            </div>
            <div class="kpi">
              <div class="label">OWASP posture</div>
              <div class="value">{kpi(owasp_pct)}</div>
              <div class="bar"><i style="width:{owasp_pct}%"></i></div>
              <div class="sub">Code + governance risk labeling</div>
            </div>
            <div class="kpi">
              <div class="label">EPSS exposure</div>
              <div class="value">{kpi(epss_pct)}</div>
              <div class="bar"><i style="width:{epss_pct}%"></i></div>
              <div class="sub">High-risk CVEs: <b>{html_escape(epss_high)}</b> · Threshold: <b>{html_escape(epss_thr)}</b></div>
            </div>
            <div class="kpi">
              <div class="label">SLA reliability</div>
              <div class="value">{kpi(sla_pct)}</div>
              <div class="bar"><i style="width:{sla_pct}%"></i></div>
              <div class="sub">SLA breaches tracked from DefectDojo aging</div>
            </div>
          </div>

          <p class="small" style="margin-top:14px;">
            <b>Executive interpretation:</b> a lower score is not “bad engineering” — it is visibility.
            The program improves by reducing high-risk exposure and tightening remediation time.
          </p>
        </div>
      </div>

      <div class="card col6">
        <div class="hd">
          <h2>ASVS Coverage</h2>
          <span class="pill">Coverage: {asvs_pct}%</span>
        </div>
        <div class="bd">
          <div class="row" style="margin-bottom:10px;">
            <span class="pill">Total: {html_escape(asvs_total)}</span>
            <span class="pill">Passed: {html_escape(asvs_passed)}</span>
            <span class="pill">Failed: {html_escape(asvs_failed)}</span>
          </div>
          <div class="bar"><i style="width:{asvs_pct}%"></i></div>
          <p class="small" style="margin-top:10px;">
            {html_escape(legacy_note) if legacy_note else "ASVS coverage indicates how well controls are evidenced and enforced by the pipeline."}
          </p>

          <h3 style="margin:14px 0 8px; font-size:13px; color:#cfe0ff; text-transform:uppercase; letter-spacing:0.4px;">Top Controls (Fail first)</h3>
          <table>
            <thead>
              <tr><th>Control</th><th>Level</th><th>Status</th><th>Evidence</th></tr>
            </thead>
            <tbody>
              {"".join([
                f"<tr>"
                f"<td><span class='pill'>{html_escape(x.get('id'))}</span></td>"
                f"<td>{html_escape(x.get('level'))}</td>"
                f"<td><span class='status {html_escape((x.get('status') or 'NOT_APPLICABLE').upper())}'>{html_escape((x.get('status') or 'NOT_APPLICABLE').upper())}</span></td>"
                f"<td class='small'>{html_escape(', '.join((x.get('evidence') or [])[:3]))}</td>"
                f"</tr>"
                for x in top10
              ]) if top10 else "<tr><td colspan='4' class='small'>No ASVS controls found (yet).</td></tr>"}
            </tbody>
          </table>
        </div>
      </div>

      <div class="card col6">
        <div class="hd">
          <h2>Exposure Hotspots</h2>
          <span class="pill">Assets: {len(assets)}</span>
        </div>
        <div class="bd">
          <h3 style="margin:0 0 8px; font-size:13px; color:#cfe0ff; text-transform:uppercase; letter-spacing:0.4px;">Top EPSS CVEs</h3>
          <table>
            <thead><tr><th>CVE</th><th>EPSS</th><th>Package</th></tr></thead>
            <tbody>
              {"".join([
                f"<tr><td><span class='pill'>{html_escape(c.get('cve'))}</span></td>"
                f"<td>{html_escape(c.get('epss'))}</td>"
                f"<td class='small'>{html_escape(c.get('package',''))}</td></tr>"
                for c in (top_cves[:8] if isinstance(top_cves, list) else [])
              ]) if (isinstance(top_cves, list) and top_cves) else "<tr><td colspan='3' class='small'>No EPSS high-risk CVEs reported.</td></tr>"}
            </tbody>
          </table>

          <h3 style="margin:14px 0 8px; font-size:13px; color:#cfe0ff; text-transform:uppercase; letter-spacing:0.4px;">SLA Breaches by Severity</h3>
          <table>
            <thead><tr><th>Severity</th><th>Count</th></tr></thead>
            <tbody>
              {"".join([
                f"<tr><td><span class='pill'>{html_escape(k)}</span></td><td>{html_escape(v)}</td></tr>"
                for k, v in sorted(sla_breaches.items(), key=lambda x: str(x[0]))
              ]) if isinstance(sla_breaches, dict) and sla_breaches else "<tr><td colspan='2' class='small'>No SLA breach breakdown available.</td></tr>"}
            </tbody>
          </table>

          <p class="small" style="margin-top:12px;">
            <b>Note:</b> “FAIL” should be read as <i>actionable signal</i>. The goal is to reduce exploitability (EPSS/KEV)
            and improve time-to-remediate (SLA), not to hide findings.
          </p>
        </div>
      </div>

      <div class="card">
        <div class="hd"><h2>Asset Scores</h2><span class="pill">Risk-aware prioritization</span></div>
        <div class="bd">
          <table>
            <thead><tr><th>Asset</th><th>Overall</th><th>OWASP</th><th>EPSS</th><th>SLA</th></tr></thead>
            <tbody>
              {"".join([
                f"<tr>"
                f"<td><b>{html_escape(a.get('name'))}</b><div class='small'>{html_escape(a.get('type',''))}</div></td>"
                f"<td>{html_escape(safe_get(a, ['score','overall'], ''))}</td>"
                f"<td>{html_escape(safe_get(a, ['score','owasp'], ''))}</td>"
                f"<td>{html_escape(safe_get(a, ['score','epss'], ''))}</td>"
                f"<td>{html_escape(safe_get(a, ['score','sla'], ''))}</td>"
                f"</tr>"
                for a in (assets if isinstance(assets, list) else [])
              ]) if isinstance(assets, list) and assets else "<tr><td colspan='5' class='small'>No assets defined in scorecard.</td></tr>"}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <div class="foot">
      This dashboard is auto-generated. Source of truth: <span class="pill">docs/data/security-scorecard.json</span>
      {f" · ASVS: <span class='pill'>{html_escape(str(asvs_path))}</span>" if asvs_path else ""}
      <br/>Generated at {html_escape(iso_now())}.
      <br/><a href="../../index.html">Back to Home</a>
    </div>
  </div>
</body>
</html>
"""

    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "index.html").write_text(html, encoding="utf-8")
    print("[OK] ASVS dashboard generated:", outdir / "index.html")


if __name__ == "__main__":
    main()
