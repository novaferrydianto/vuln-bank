#!/usr/bin/env python3
import json
import os
import sys

def load_json(path):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}

def main():
    # Load data dari job sebelumnya
    epss_data = load_json("reports/epss-findings.json")
    sonar_issues = load_json("reports/sonar-issues.json")
    sonar_hotspots = load_json("reports/sonar-hotspots.json")
    
    high_risk_vulns = epss_data.get("high_risk", [])
    sonar_total = len(sonar_issues.get("issues", []))
    hotspot_total = len(sonar_hotspots.get("hotspots", []))

    # Mulai membangun Markdown
    summary = []
    summary.append("### 🛡️ DevSecOps Executive Summary")
    summary.append(f"Hasil analisis risiko untuk commit: `{os.getenv('GITHUB_SHA', 'N/A')[:7]}`\n")
    
    # Bagian 1: Vulnerability Intel (EPSS/KEV)
    summary.append("#### 🚀 Threat Intelligence (Trivy + EPSS)")
    if high_risk_vulns:
        summary.append("| CVE ID | Severity | EPSS | KEV | Reasons |")
        summary.append("| :--- | :--- | :--- | :--- | :--- |")
        for v in high_risk_vulns[:10]: # Tampilkan top 10
            kev_icon = "⚠️ YES" if v['is_kev'] else "No"
            summary.append(f"| `{v['cve']}` | {v['severity']} | {v['epss']:.4f} | {kev_icon} | {', '.join(v['reasons'])} |")
        
        if len(high_risk_vulns) > 10:
            summary.append(f"\n*...dan {len(high_risk_vulns) - 10} temuan berisiko tinggi lainnya.*")
    else:
        summary.append("✅ Tidak ada kerentanan berisiko tinggi (EPSS/KEV) terdeteksi.")

    # Bagian 2: SonarQube Summary
    summary.append("\n#### 🔍 Code Quality & Security (SonarQube)")
    summary.append(f"- **Issues Terdeteksi:** {sonar_total}")
    summary.append(f"- **Security Hotspots:** {hotspot_total}")
    
    status_icon = "❌ FAILED" if high_risk_vulns else "✅ PASSED"
    summary.append(f"\n**Pipeline Gate Status:** {status_icon}")

    # Kirim ke GitHub Summary
    summary_text = "\n".join(summary)
    
    summary_file = os.getenv('GITHUB_STEP_SUMMARY')
    if summary_file:
        with open(summary_file, "a") as f:
            f.write(summary_text)
    else:
        print(summary_text)

if __name__ == "__main__":
    main()