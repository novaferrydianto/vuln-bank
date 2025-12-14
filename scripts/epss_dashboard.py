#!/usr/bin/env python3
"""
Vuln Bank – Risk-Aware EPSS / KEV Dashboard
------------------------------------------

Static HTML dashboard with:
- Executive overview (PASS / FAIL)
- Risk drivers (EPSS, KEV, CVSS)
- Remediation plan (SLA-aware)
- Weekly trend persistence (PASS %, KEV count)

Pages generated:
- index.html
- risks.html
- remediation.html

Artifacts:
- remediation.json
- security-metrics/weekly/epss-trend.jsonl

Safe for:
- GitHub Pages
- CI/CD automation
- Missing / partial data
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# =====================================================
# CLI
# =====================================================

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True, help="Path to epss-findings.json")
    p.add_argument("--outdir", required=True, help="Output directory (site/)")
    return p.parse_args()

# =====================================================
# Models
# =====================================================

@dataclass
class Finding:
    cve: str
    pkg: str
    severity: str
    epss: float
    percentile: float
    is_kev: bool
    cvss: Optional[float]
    installed: Optional[str]
    fixed: Optional[str]
    target: Optional[str]
    reasons: List[str]
    description: Optional[str]
    priority: float

# =====================================================
# Utilities
# =====================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

def clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))

def sf(v: Any, d: float = 0.0) -> float:
    try:
        return float(v)
    except Exception:
        return d

def ss(v: Any, d: str = "") -> str:
    return "" if v is None else str(v)

def esc(s: str) -> str:
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
         .replace("'", "&#39;")
    )

# =====================================================
# Risk Logic
# =====================================================

def compute_priority(epss: float, cvss: Optional[float], is_kev: bool, sev: str) -> float:
    score = clamp(epss, 0, 1) * 60
    score += clamp(sf(cvss), 0, 10) * 3
    if is_kev:
        score += 20
    if sev.upper() == "CRITICAL":
        score += 10
    return round(score, 2)

def sla_from_priority(score: float, is_kev: bool, sev: str) -> Tuple[str, str]:
    if is_kev or score >= 85:
        return "24h", "P0 – Immediate"
    if sev == "CRITICAL" or score >= 70:
        return "48h", "P1 – High"
    if score >= 50:
        return "7d", "P2 – Medium"
    return "30d", "P3 – Low"

def remediation_text(f: Finding) -> str:
    if f.fixed:
        if f.installed:
            return f"Upgrade `{f.pkg}` {f.installed} → {f.fixed}"
        return f"Upgrade `{f.pkg}` → {f.fixed}"
    return f"Mitigate `{f.pkg}` (no fix yet): WAF, config hardening, monitoring"

def reason_summary(f: Finding, thr: float) -> str:
    r = []
    if f.is_kev:
        r.append("CISA KEV")
    if f.epss >= thr:
        r.append(f"EPSS ≥ {thr}")
    if f.cvss and f.cvss >= 9:
        r.append("CVSS ≥ 9")
    if f.severity == "CRITICAL":
        r.append("CRITICAL severity")
    r.extend([x for x in f.reasons if x not in r])
    return ", ".join(r) or "Risk signal detected"

# =====================================================
# Loaders
# =====================================================

def load_findings(path: Path) -> Tuple[float, List[Finding]]:
    data = json.loads(path.read_text())
    thr = sf(data.get("threshold"), 0.5)
    rows = data.get("high_risk") or []

    findings: List[Finding] = []

    for r in rows:
        epss = sf(r.get("epss"))
        cvss = r.get("cvss")
        sev = ss(r.get("severity", "HIGH")).upper()
        priority = sf(r.get("priority_score")) or compute_priority(
            epss, cvss, bool(r.get("is_kev")), sev
        )

        findings.append(
            Finding(
                cve=ss(r.get("cve"), "UNKNOWN"),
                pkg=ss(r.get("pkg_name"), "unknown"),
                severity=sev,
                epss=epss,
                percentile=sf(r.get("percentile")),
                is_kev=bool(r.get("is_kev")),
                cvss=sf(cvss) if cvss is not None else None,
                installed=ss(r.get("installed_version")),
                fixed=ss(r.get("fixed_version")),
                target=ss(r.get("target")),
                reasons=r.get("reasons") or [],
                description=ss(r.get("description")),
                priority=priority,
            )
        )

    findings.sort(key=lambda x: x.priority, reverse=True)
    return thr, findings

# =====================================================
# Weekly Trend Persistence
# =====================================================

def write_weekly_trend(findings: List[Finding], thr: float):
    out = Path("security-metrics/weekly/epss-trend.jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)

    rec = {
        "week": datetime.utcnow().strftime("%Y-W%U"),
        "generated_at": now_iso(),
        "pass_percent": 100.0 if not findings else 0.0,
        "kev_count": sum(1 for f in findings if f.is_kev),
        "high_risk": len(findings),
        "threshold": thr,
    }

    with out.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")

# =====================================================
# HTML Base
# =====================================================

def html_base(title: str, body: str) -> str:
    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{esc(title)}</title>
<link rel="stylesheet" href="../dashboards/asvs/styles.css"/>
</head>
<body>
<div class="wrap">
<nav class="nav">
<a href="index.html">Overview</a>
<a href="risks.html">Risks</a>
<a href="remediation.html">Remediation</a>
</nav>
{body}
<footer class="footer">Vuln Bank · Risk-Aware DevSecOps</footer>
</div>
</body>
</html>
"""

# =====================================================
# Pages
# =====================================================

def render_index(findings: List[Finding], thr: float) -> str:
    status = "PASS" if not findings else "FAIL"
    badge = "✅ PASS" if status == "PASS" else "🚨 ACTION REQUIRED"

    bullets = [
        f"High-risk findings: {len(findings)}",
        f"CISA KEV matches: {sum(1 for f in findings if f.is_kev)}",
        f"EPSS threshold: {thr}",
    ]

    body = f"""
<section class="card">
<h2>{badge}</h2>
<p><b>{status}</b> – EPSS / KEV risk evaluation</p>
<ul>
{''.join(f'<li>{esc(b)}</li>' for b in bullets)}
</ul>
<p class="muted">Generated: {now_iso()}</p>
</section>
"""
    return html_base("EPSS / KEV Overview", body)

def render_risks(findings: List[Finding], thr: float) -> str:
    if not findings:
        return html_base("Risks", "<section class='card'>No high-risk findings.</section>")

    rows = ""
    for f in findings:
        rows += f"""
<tr>
<td>{esc(f.cve)}</td>
<td>{esc(f.pkg)}</td>
<td>{f.severity}</td>
<td>{f.epss:.4f}</td>
<td>{f.cvss or ''}</td>
<td>{f.priority}</td>
<td>{esc(reason_summary(f, thr))}</td>
</tr>
"""

    body = f"""
<section class="card">
<h2>High-Risk Vulnerabilities</h2>
<table>
<thead>
<tr><th>CVE</th><th>Package</th><th>Severity</th><th>EPSS</th><th>CVSS</th><th>Priority</th><th>Signals</th></tr>
</thead>
<tbody>{rows}</tbody>
</table>
</section>
"""
    return html_base("Risks", body)

def render_remediation(findings: List[Finding], thr: float) -> str:
    if not findings:
        return html_base("Remediation", "<section class='card'>No remediation required.</section>")

    rows = ""
    for f in findings:
        sla, urg = sla_from_priority(f.priority, f.is_kev, f.severity)
        rows += f"""
<tr>
<td>{esc(f.cve)}</td>
<td>{esc(f.pkg)}</td>
<td>{f.severity}</td>
<td>{f.priority}</td>
<td>{urg}</td>
<td>{sla}</td>
<td>{esc(remediation_text(f))}</td>
</tr>
"""

    body = f"""
<section class="card">
<h2>Remediation Plan</h2>
<table>
<thead>
<tr><th>CVE</th><th>Package</th><th>Severity</th><th>Priority</th><th>Urgency</th><th>SLA</th><th>Action</th></tr>
</thead>
<tbody>{rows}</tbody>
</table>
</section>
"""
    return html_base("Remediation", body)

# =====================================================
# Main
# =====================================================

def main():
    args = parse_args()
    inp = Path(args.input)
    out = Path(args.outdir)

    out.mkdir(parents=True, exist_ok=True)

    thr, findings = load_findings(inp)

    write_weekly_trend(findings, thr)

    (out / "index.html").write_text(render_index(findings, thr))
    (out / "risks.html").write_text(render_risks(findings, thr))
    (out / "remediation.html").write_text(render_remediation(findings, thr))

    print(f"[OK] EPSS dashboard generated → {out}")

if __name__ == "__main__":
    main()
