#!/usr/bin/env python3
"""
Render Security Scorecard JSON into a board-friendly Markdown report.

Usage (pipeline):
  python3 scripts/render_security_markdown.py docs/data/security-scorecard.json \
    > docs/reports/security-board-report.md
"""

import json
import sys
from datetime import datetime


def safe_load_json(path: str):
    """Load JSON scorecard; return None on error."""
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as exc:  # noqa: BLE001
        print(f"[WARN] Failed to load scorecard JSON: {exc}", file=sys.stderr)
        return None


def fmt_traffic_light(color: str) -> str:
    if color == "green":
        return "🟢 Green"
    if color == "yellow":
        return "🟡 Yellow"
    if color == "red":
        return "🔴 Red"
    return color or "N/A"


def _signal_from_norm(norm: float) -> str:
    try:
        value = float(norm)
    except Exception:  # noqa: BLE001
        value = 0.0
    if value >= 0.8:
        return "green"
    if value >= 0.6:
        return "yellow"
    return "red"


def main() -> None:
    if len(sys.argv) < 2:
        print("# Security Board Report\n\nScorecard JSON path not provided.")
        return

    path = sys.argv[1]
    data = safe_load_json(path)
    if not data:
        print("# Security Board Report\n\nUnable to load security scorecard.")
        return

    metadata = data.get("metadata", {}) or {}
    overall = data.get("overall", {}) or {}
    comps = data.get("components", {}) or {}

    app = metadata.get("app_name", "vuln-bank")
    generated = metadata.get("generated_at")

    owasp = comps.get("owasp", {}) or {}
    epss = comps.get("epss", {}) or {}
    sla = comps.get("sla", {}) or {}

    overall_score = overall.get("score", 0)
    overall_grade = overall.get("grade", "-")
    overall_signal = fmt_traffic_light(overall.get("traffic_light"))
    summary_en = overall.get("summary_en", "")
    summary_id = overall.get("summary_id", "")

    ts_local = generated or datetime.utcnow().isoformat() + "Z"

    md: list[str] = []

    # Title
    md.append("# Vuln Bank Security Posture — Board Report")
    md.append("")
    md.append(f"_Generated at: {ts_local}_")
    md.append(f"_Application: **{app}**_")
    md.append("")

    # 1. Executive Summary
    md.append("## 1. Executive Summary / Ringkasan Eksekutif")
    md.append("")
    md.append(
        f"- **Overall Score / Skor Keseluruhan**: "
        f"**{overall_score}** ({overall_grade}) – {overall_signal}",
    )
    md.append(f"- **EN**: {summary_en}")
    md.append(f"- **ID**: {summary_id}")
    md.append("")

    # 2. KPI Table
    md.append("## 2. Key Security KPIs")
    md.append("")
    md.append("| Component | Score | Signal | Notes |")
    md.append("|----------|-------|--------|-------|")

    o_sig = fmt_traffic_light(_signal_from_norm(owasp.get("normalized", 0)))
    e_sig = fmt_traffic_light(_signal_from_norm(epss.get("normalized", 0)))
    s_sig = fmt_traffic_light(_signal_from_norm(sla.get("normalized", 0)))

    md.append(
        "| OWASP / ASVS | "
        f"{owasp.get('score', 'N/A')} | "
        f"{o_sig} | "
        "Coverage of secure coding and control implementation |",
    )

    md.append(
        "| EPSS / KEV Exposure | "
        f"{epss.get('score', 'N/A')} | "
        f"{e_sig} | "
        "Real-world exploit likelihood & KEV alignment |",
    )

    md.append(
        "| SLA / Vulnerability Aging | "
        f"{sla.get('score', 'N/A')} | "
        f"{s_sig} | "
        "Timeliness of remediation vs SLA |",
    )
    md.append("")

    # 3. Component Details
    md.append("## 3. Component Details / Detail Komponen")
    md.append("")

    # 3.1 OWASP
    md.append("### 3.1 OWASP / ASVS Coverage")
    md.append("")
    md.append(
        "**EN**: This reflects how well the application aligns with "
        "OWASP ASVS controls and secure coding practices.",
    )
    md.append(
        "**ID**: Bagian ini menunjukkan seberapa baik aplikasi mengikuti kontrol "
        "OWASP ASVS dan praktik secure coding.",
    )
    md.append("")
    o_details = owasp.get("details", {}) or {}
    note = o_details.get("note")
    if note:
        md.append(f"- Note: {note}")
    md.append(f"- Score: **{owasp.get('score', 'N/A')}**")
    md.append("")

    # 3.2 EPSS
    md.append("### 3.2 EPSS + CISA KEV Exposure")
    md.append("")
    md.append(
        "**EN**: This measures concentration of high-risk CVEs with high EPSS "
        "scores and KEV alignment.",
    )
    md.append(
        "**ID**: Bagian ini mengukur konsentrasi CVE berisiko tinggi dengan skor "
        "EPSS tinggi dan tercatat di CISA KEV.",
    )
    md.append("")
    e_details = epss.get("details", {}) or {}
    md.append(f"- High-Risk CVEs: **{e_details.get('high_risk_count', 0)}**")
    md.append(f"- KEV CVEs: **{e_details.get('kev_count', 0)}**")
    md.append(
        f"- Mode: `{e_details.get('mode', '-')}`, "
        f"Threshold: `{e_details.get('threshold', '-')}`",
    )
    md.append(f"- Component Score: **{epss.get('score', 'N/A')}**")
    md.append("")

    # 3.3 SLA
    md.append("### 3.3 SLA & Vulnerability Aging")
    md.append("")
    md.append(
        "**EN**: This tracks how many critical/high vulnerabilities are "
        "breaching or close to breaching SLA.",
    )
    md.append(
        "**ID**: Bagian ini memantau berapa banyak vulnerability critical/high "
        "yang sudah atau hampir melampaui SLA perbaikan.",
    )
    md.append("")
    s_details = sla.get("details", {}) or {}
    md.append(f"- Open Critical: **{s_details.get('open_critical', 0)}**")
    md.append(f"- Open High: **{s_details.get('open_high', 0)}**")
    md.append(
        "- SLA Breached / Melewati SLA: "
        f"**{s_details.get('breached', 0)}**",
    )
    md.append(
        "- Near Breach / Hampir melewati SLA: "
        f"**{s_details.get('near_breach', 0)}**",
    )
    md.append(f"- Risk Points: **{s_details.get('risk_points', 0)}**")
    md.append(f"- Component Score: **{sla.get('score', 'N/A')}**")
    md.append("")

    # 4. Recommendations
    md.append("## 4. Recommended Next Actions / Rekomendasi Aksi Lanjutan")
    md.append("")
    md.append("**EN:**")
    md.append("- Prioritize remediation of KEV-linked CVEs and those with the highest EPSS score.")
    md.append("- Improve coverage on missing or weak OWASP/ASVS controls detected in latest assessments.")
    md.append("- Reduce SLA breaches by enforcing stricter triage and ownership for critical/high findings.")
    md.append("")
    md.append("**ID:**")
    md.append("- Prioritaskan perbaikan CVE yang masuk daftar KEV dan memiliki skor EPSS tertinggi.")
    md.append("- Tingkatkan coverage terhadap kontrol OWASP/ASVS yang masih lemah atau belum terpenuhi.")
    md.append("- Kurangi pelanggaran SLA dengan penugasan yang lebih tegas untuk temuan critical/high.")
    md.append("")

    print("\n".join(md))


if __name__ == "__main__":
    main()
