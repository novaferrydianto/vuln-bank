#!/usr/bin/env python3
import os, json, datetime

def load_json(path):
    if not os.path.isfile(path):
        return {}
    with open(path) as f:
        return json.load(f)

def main():
    REPORT = os.environ.get("REPORT_DIR", "security-reports")
    path = f"{REPORT}/epss-findings.json"

    data = load_json(path)

    threshold = data.get("threshold", 0)
    total = data.get("total_trivy_high_crit", 0)
    high_risk = data.get("high_risk", [])

    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    print(f"## 🛡️ Security Intelligence Dashboard\n")
    print(f"Generated at: `{ts}`  ")
    print(f"EPSS Threshold: `{threshold}`  \n")

    print("### 📊 Summary Statistics\n")
    print(f"- 🔍 **Total Unique CVEs:** {total}")
    print(f"- ⚠️ **High-Risk Findings:** {len(high_risk)}")
    print(f"- 🎛️ **Gate Status:** {'❌ FAIL' if len(high_risk)>0 else '✅ PASS'}\n")

    print("### 🧨 High-Risk Vulnerabilities (Prioritized)\n")

    if len(high_risk) == 0:
        print("| Severity | CVE ID | EPSS Score | CVSS | Reasons | Sources |")
        print("|----------|--------|-------------|------|----------|---------|")
        print("| - | No high-risk vulnerabilities found | - | - | - | - |")
        return

    print("| Severity | CVE ID | EPSS Score | CVSS | Reasons | Sources |")
    print("|----------|--------|-------------|------|----------|---------|")

    for item in high_risk:
        sev = item.get("severity", "-")
        cve = item.get("cve", "-")
        epss = item.get("epss", "-")
        cvss = item.get("cvss", "-")
        reasons = ",".join(item.get("reasons", []))
        pkg = item.get("pkg_name", "-")

        print(f"| {sev} | {cve} | {epss} | {cvss} | {reasons} | {pkg} |")

    print("\n_Summary generated at run-time_")

if __name__ == "__main__":
    main()
