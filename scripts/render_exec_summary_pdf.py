#!/usr/bin/env python3
import json
import os
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

def main():
    src = "docs/data/security-scorecard.json"
    out = "docs/executive-summary.pdf"
    os.makedirs("docs", exist_ok=True)

    data = json.load(open(src, "r", encoding="utf-8"))

    c = canvas.Canvas(out, pagesize=A4)
    w, h = A4

    y = h - 72
    def line(txt, size=12, dy=18):
        nonlocal y
        c.setFont("Helvetica", size)
        c.drawString(72, y, txt)
        y -= dy

    line("Vuln Bank – Weekly Security Executive Summary", 16, 26)
    line(f"Repository: {data.get('repo')}", 11)
    line(f"Generated: {data.get('generated_at')}", 11)
    line("", 11, 10)

    score = data.get("score", {})
    line(f"Overall Score: {score.get('overall')} / 100 (Grade {data.get('grade')})", 14, 24)
    line(f"OWASP: {score.get('owasp')} | EPSS: {score.get('epss')} | SLA: {score.get('sla')}", 11)

    line("", 11, 14)
    line("Key Signals", 13, 20)

    owasp = data.get("owasp", {})
    line("OWASP (7d): " + ", ".join([f"{k}={v}" for k,v in owasp.items()]) if owasp else "OWASP (7d): none")

    epss = data.get("epss", {})
    line(f"EPSS high-risk count: {epss.get('high_risk_count', 0)}")
    top = (epss.get("top_cves") or [])[:1]
    if top:
        t = top[0]
        line(f"Top CVE: {t.get('cve')} (EPSS {t.get('epss')}) pkg={t.get('package')}")
    else:
        line("Top CVE: none")

    sla = (data.get("sla") or {}).get("breaches", {})
    if sla:
        line("SLA breaches: " + ", ".join([f"{k}={v}" for k,v in sla.items()]))
    else:
        line("SLA breaches: none")

    line("", 11, 14)
    line("Next 7 Days Actions", 13, 20)
    line("1) Patch/mitigate EPSS-high items first (KEV/EPSS priority).")
    line("2) A01/A02 hardening: authz checks + transport/cookie/TLS controls.")
    line("3) SLA burn-down: owners + weekly review + escalation on breach.")

    c.showPage()
    c.save()
    print("[OK] wrote", out)

if __name__ == "__main__":
    main()
