#!/usr/bin/env python3
"""
Slack Notification – Governance Enriched

Sources:
- asvs-labels.json
- epss-findings.json (optional)
- zap_alerts.json (optional)
- gate_failed marker

Outputs:
- Structured Slack message
"""

import json
import os
from pathlib import Path
import urllib.request

SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL")
REPO = os.getenv("GITHUB_REPOSITORY", "unknown")
RUN_ID = os.getenv("GITHUB_RUN_ID", "manual")
PR = os.getenv("PR_NUMBER")

BASE = Path("security-reports")
ASVS = BASE / "governance/asvs-labels.json"
EPSS = BASE / "epss-findings.json"
ZAP = BASE / "zap/zap_alerts.json"
GATE = BASE / "gate_failed"

def load(p):
    return json.loads(p.read_text()) if p.exists() else {}

def main():
    if not SLACK_WEBHOOK:
        print("[SKIP] No Slack webhook")
        return

    asvs = load(ASVS)
    epss = load(EPSS)
    zap = load(ZAP)

    risk_labels = asvs.get("risk_labels", [])
    owasp = asvs.get("owasp_labels", [])
    asvs_delta = asvs.get("asvs_delta", [])

    # --------------------------------------------------
    # Headline
    # --------------------------------------------------
    if GATE.exists():
        status = "🚨 *SECURITY GATE FAILED*"
    elif "risk:high" in risk_labels:
        status = "🔴 *HIGH RISK DETECTED*"
    elif "risk:medium" in risk_labels:
        status = "🟠 *MEDIUM RISK DETECTED*"
    else:
        status = "🟢 *SECURITY CHECK PASSED*"

    lines = [
        status,
        f"*Repository:* `{REPO}`",
        f"*Run ID:* `{RUN_ID}`",
    ]

    if PR:
        lines.append(f"*PR:* `#{PR}`")

    lines.append("")

    # --------------------------------------------------
    # ASVS / OWASP
    # --------------------------------------------------
    if asvs_delta:
        lines.append("*ASVS Delta:*")
        for a in asvs_delta[:6]:
            lines.append(f"• `{a}`")

    if owasp:
        lines.append("")
        lines.append("*OWASP Categories:*")
        for o in owasp:
            lines.append(f"• `{o}`")

    # --------------------------------------------------
    # EPSS
    # --------------------------------------------------
    high_risk = epss.get("high_risk", [])
    if high_risk:
        max_epss = max(v.get("epss", 0) for v in high_risk)
        lines.append("")
        lines.append(f"*EPSS Max:* `{max_epss:.2f}`")
        for v in high_risk[:3]:
            lines.append(
                f"• `{v.get('cve')}` EPSS `{v.get('epss'):.2f}` ({', '.join(v.get('reasons', []))})"
            )

    # --------------------------------------------------
    # ZAP Summary
    # --------------------------------------------------
    if zap:
        alerts = zap.get("site", [{}])[0].get("alerts", [])
        if alerts:
            sev = {}
            for a in alerts:
                s = a.get("riskdesc", "unknown")
                sev[s] = sev.get(s, 0) + 1
            lines.append("")
            lines.append("*ZAP Alerts:*")
            for k, v in sev.items():
                lines.append(f"• {k}: `{v}`")

    payload = {"text": "\n".join(lines)}

    req = urllib.request.Request(
        SLACK_WEBHOOK,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(req, timeout=10)
    print("[OK] Slack notification sent")

if __name__ == "__main__":
    main()
