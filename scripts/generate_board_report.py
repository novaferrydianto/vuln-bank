#!/usr/bin/env python3
"""
Board-Style Security Report (PDF with Charts)

Reads:
  - docs/data/security-scorecard.json
Optionally reads:
  - docs/data/governance/asvs-coverage.json  (preferred)
  - security-reports/governance/asvs-coverage.json (fallback)

Outputs:
  - docs/board/board-report.pdf
"""

from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen.canvas import Canvas
from reportlab.lib.units import cm
from reportlab.lib.utils import ImageReader

import matplotlib.pyplot as plt


# -------------------------------------------------
# Utilities
# -------------------------------------------------
def read_json(p: Path) -> Dict[str, Any]:
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
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


def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)


def save_bar_chart(path: Path, title: str, labels: List[str], values: List[int]):
    plt.figure(figsize=(7.2, 3.2))
    plt.title(title)
    plt.bar(labels, values)
    plt.ylim(0, 100)
    plt.ylabel("Score (0–100)")
    plt.tight_layout()
    plt.savefig(path, dpi=160)
    plt.close()


def save_single_meter(path: Path, title: str, value: int):
    plt.figure(figsize=(7.2, 1.9))
    plt.title(title)
    plt.bar(["Maturity"], [value])
    plt.ylim(0, 100)
    plt.ylabel("0–100")
    plt.tight_layout()
    plt.savefig(path, dpi=160)
    plt.close()


# -------------------------------------------------
# Main
# -------------------------------------------------
def main():
    scorecard_path = Path("docs/data/security-scorecard.json")
    asvs_docs = Path("docs/data/governance/asvs-coverage.json")
    asvs_fallback = Path("security-reports/governance/asvs-coverage.json")

    scorecard = read_json(scorecard_path)
    asvs = read_json(asvs_docs) or read_json(asvs_fallback)

    outdir = Path("docs/board")
    tmpdir = outdir / "_tmp"
    ensure_dir(outdir)
    ensure_dir(tmpdir)

    # -------------------------------------------------
    # Extract scorecard values
    # -------------------------------------------------
    repo = safe_get(scorecard, ["meta", "repo"], "unknown")
    gen = safe_get(scorecard, ["meta", "generated_at"], iso_now())
    version = safe_get(scorecard, ["meta", "version"], "unknown")

    maturity = int(safe_get(scorecard, ["score", "overall"], 0) or 0)
    grade = safe_get(scorecard, ["score", "grade"], "N/A")
    owasp = int(safe_get(scorecard, ["score", "components", "owasp"], 0) or 0)
    epss = int(safe_get(scorecard, ["score", "components", "epss"], 0) or 0)
    sla = int(safe_get(scorecard, ["score", "components", "sla"], 0) or 0)

    epss_high = int(safe_get(scorecard, ["epss", "high_risk_count"], 0) or 0)
    top_cves = safe_get(scorecard, ["epss", "top_cves"], []) or []
    breaches_by_sev = safe_get(scorecard, ["sla", "breaches_by_severity"], {}) or {}
    mgmt = safe_get(scorecard, ["management_summary"], {}) or {}

    # -------------------------------------------------
    # Charts
    # -------------------------------------------------
    meter_png = tmpdir / "maturity.png"
    comp_png = tmpdir / "components.png"
    save_single_meter(meter_png, "Security Maturity Score (0–100)", maturity)
    save_bar_chart(comp_png, "Component Scores", ["OWASP", "EPSS", "SLA"], [owasp, epss, sla])

    # -------------------------------------------------
    # PDF init
    # -------------------------------------------------
    pdf_path = outdir / "board-report.pdf"
    c = Canvas(str(pdf_path), pagesize=A4)
    W, H = A4

    def text(x, y, s, size=10, bold=False):
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        c.drawString(x, y, s)

    # =================================================
    # PAGE 1 — BOARD SUMMARY
    # =================================================
    text(2*cm, H-2.2*cm, "Vuln Bank — Board Security Brief", 16, True)
    text(2*cm, H-2.9*cm, f"Repo: {repo} | Version: {version} | Generated: {gen}", 9)

    y0 = H - 4.0*cm
    text(2*cm, y0, f"Maturity: {maturity}/100", 12, True)
    text(8*cm, y0, f"Grade: {grade}", 12, True)
    text(12.2*cm, y0, f"EPSS High-Risk: {epss_high}", 12, True)

    c.drawImage(ImageReader(str(meter_png)), 2*cm, H-9*cm, width=17*cm, height=3.8*cm)
    c.drawImage(ImageReader(str(comp_png)), 2*cm, H-13.6*cm, width=17*cm, height=5*cm)

    y = H - 14.6*cm
    text(2*cm, y, "Executive Interpretation", 12, True)
    y -= 0.6*cm

    bullets = [
        "FAIL is a signal, not a blame marker — it enables early risk visibility.",
        "Primary objective: reduce exploitability (EPSS) and remediation latency (SLA).",
        "Maturity rises as high-risk findings shrink and evidence stabilizes."
    ]

    c.setFont("Helvetica", 10)
    for b in bullets:
        c.drawString(2.3*cm, y, f"• {b}")
        y -= 0.52*cm

    y -= 0.2*cm
    text(2*cm, y, "Recommended Actions (Next 7 Days)", 12, True)
    y -= 0.6*cm

    for r in mgmt.get("recommended_actions", [])[:5]:
        c.drawString(2.3*cm, y, f"• {r}")
        y -= 0.52*cm

    c.showPage()

    # =================================================
    # PAGE 2 — EPSS & SLA DETAILS
    # =================================================
    text(2*cm, H-2.2*cm, "Exposure & Remediation Status", 14, True)
    text(2*cm, H-2.9*cm, f"Generated: {iso_now()}", 9)

    y = H - 4.0*cm
    text(2*cm, y, "Top EPSS CVEs", 12, True)
    y -= 0.6*cm

    c.setFont("Helvetica-Bold", 9)
    c.drawString(2*cm, y, "CVE")
    c.drawString(7*cm, y, "EPSS")
    c.drawString(10*cm, y, "Package")
    y -= 0.4*cm
    c.setFont("Helvetica", 9)

    for row in top_cves[:10]:
        c.drawString(2*cm, y, row.get("cve", "")[:30])
        c.drawString(7*cm, y, str(row.get("epss", "")))
        c.drawString(10*cm, y, row.get("package", "")[:40])
        y -= 0.35*cm

    y -= 0.5*cm
    text(2*cm, y, "SLA Breaches by Severity", 12, True)
    y -= 0.6*cm

    for sev, cnt in breaches_by_sev.items():
        c.drawString(2*cm, y, f"{sev}: {cnt}")
        y -= 0.35*cm

    c.showPage()

    # =================================================
    # PAGE 3 — ASVS CONTROL COVERAGE
    # =================================================
    controls = asvs.get("controls", []) if isinstance(asvs, dict) else []

    text(2*cm, H-2.2*cm, "ASVS Control Coverage (Risk-First View)", 14, True)
    text(2*cm, H-2.9*cm, f"Generated: {iso_now()}", 9)

    y = H - 4.2*cm
    c.setFont("Helvetica-Bold", 9)
    c.drawString(2*cm, y, "Control")
    c.drawString(5.5*cm, y, "Level")
    c.drawString(7*cm, y, "Status")
    c.drawString(9.5*cm, y, "Evidence")
    y -= 0.4*cm
    c.setFont("Helvetica", 9)

    priority = {"FAIL": 0, "PASS": 1, "NOT_APPLICABLE": 2}
    controls = sorted(controls, key=lambda x: (priority.get(x.get("status"), 3), x.get("id", "")))

    for item in controls[:120]:
        if y < 3*cm:
            c.showPage()
            y = H - 3.5*cm

        c.drawString(2*cm, y, item.get("id", "")[:28])
        c.drawString(5.5*cm, y, str(item.get("level", "")))
        c.drawString(7*cm, y, item.get("status", ""))
        c.drawString(9.5*cm, y, ", ".join(item.get("evidence", []))[:60])
        y -= 0.35*cm

    c.save()
    print("[OK] Board report generated:", pdf_path)


if __name__ == "__main__":
    main()
