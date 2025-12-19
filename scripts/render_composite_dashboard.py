#!/usr/bin/env python3
import json
import os
from datetime import datetime

def get_severity_emoji(cvss):
    if cvss >= 9.0: return "🔴 CRITICAL"
    if cvss >= 7.0: return "🟠 HIGH"
    if cvss >= 4.0: return "🟡 MEDIUM"
    return "🔵 LOW"

def render():
    input_file = os.getenv("COMPOSITE_FINDINGS", "security-reports/epss-findings.json")
    output_file = os.getenv("COMPOSITE_DASHBOARD", "security-reports/composite-dashboard.md")

    if not os.path.exists(input_file):
        return

    # Perbaikan Ruff UP015: Parameter "r" dihapus
    with open(input_file) as f:
        data = json.load(f)

    md = [
        "# 🛡️ Security Intelligence Dashboard",
        f"**Generated at:** `{data.get('generated_at', datetime.utcnow().isoformat())}`",
        f"**EPSS Threshold:** `{data.get('threshold', 'N/A')}`",
        "\n## 📊 Summary Statistics"
    ]
    
    summary = data.get("summary", {})
    md.append(f"- 🔍 **Total Unique CVEs:** {summary.get('total_unique_cves', 0)}")
    md.append(f"- ⚠️ **High-Risk Findings:** {summary.get('high_risk_count', 0)}")
    
    status = "✅ PASS" if summary.get('high_risk_count', 0) == 0 else "❌ FAIL"
    md.append(f"- 🚦 **Gate Status:** {status}")

    md.append("\n## 🚨 High-Risk Vulnerabilities (Prioritized)")
    md.append("| Severity | CVE ID | EPSS Score | CVSS | Reasons | Sources |")
    md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")

    findings = data.get("findings", [])
    if not findings:
        md.append("| - | No high-risk vulnerabilities found | - | - | - | - |")
    else:
        for v in findings:
            severity = get_severity_emoji(v.get("cvss", 0))
            cve_id = f"[{v['cve']}](https://nvd.nist.gov/vuln/detail/{v['cve']})"
            epss = f"{v.get('epss', 0.0):.4f}"
            cvss = v.get("cvss", 0.0)
            reasons = "<br>".join([f"• {r}" for r in v.get("reasons", [])])
            sources = ", ".join(v.get("sources", []))
            md.append(f"| {severity} | {cve_id} | {epss} | {cvss} | {reasons} | {sources} |")

    with open(output_file, "w") as f:
        f.write("\n".join(md))
    
    print("\n".join(md))

if __name__ == "__main__":
    render()