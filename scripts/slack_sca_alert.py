import json
import os
import sys
import urllib.request

REPORT_DIR = os.getenv("REPORT_DIR", "security-reports")
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL")
EPSS_THRESHOLD = float(os.getenv("EPSS_THRESHOLD", "0.5"))

if not SLACK_WEBHOOK:
    print("[SKIP] SLACK_WEBHOOK_URL not set")
    sys.exit(0)

alerts = []

# ---------- SCA CRITICAL (Trivy) ----------
trivy_file = f"{REPORT_DIR}/trivy-sca.json"
if os.path.exists(trivy_file):
    data = json.load(open(trivy_file))
    for r in data.get("Results", []):
        for v in r.get("Vulnerabilities", []):
            if v.get("Severity") == "CRITICAL":
                alerts.append(
                    f"• `{v.get('VulnerabilityID')}` | {v.get('PkgName')} "
                    f"| Fixed: {v.get('FixedVersion','-')}"
                )

# ---------- EPSS HIGH ----------
epss_file = f"{REPORT_DIR}/epss-findings.json"
if os.path.exists(epss_file):
    epss = json.load(open(epss_file))
    for v in epss.get("high_risk", []):
        if float(v.get("epss", 0)) >= EPSS_THRESHOLD:
            alerts.append(
                f"• `{v.get('cve')}` | EPSS `{float(v.get('epss')):.2f}` "
                f"| {', '.join(v.get('reasons', []))}"
            )

if not alerts:
    print("[OK] No SCA Critical / High EPSS findings")
    sys.exit(0)

message = {
    "text": (
        "🚨 *SCA High-Risk Detected*\n"
        f"*Repository:* {os.getenv('GITHUB_REPOSITORY')}\n"
        f"*Run:* {os.getenv('GITHUB_SERVER_URL')}/"
        f"{os.getenv('GITHUB_REPOSITORY')}/actions/runs/"
        f"{os.getenv('GITHUB_RUN_ID')}\n\n"
        "*Findings:*\n" + "\n".join(alerts[:10])
    )
}

req = urllib.request.Request(
    SLACK_WEBHOOK,
    data=json.dumps(message).encode(),
    headers={"Content-Type": "application/json"},
)

urllib.request.urlopen(req, timeout=10)
print("[ALERT] Slack SCA notification sent")
