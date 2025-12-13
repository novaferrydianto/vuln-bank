#!/usr/bin/env python3
"""
Slack Notification – Governance Enriched (Enterprise)

Inputs (optional but expected):
- security-reports/governance/asvs-labels.json
- security-reports/epss-findings.json
- security-reports/zap/zap_alerts.json
- security-reports/gate_failed

Behavior:
- Sends Slack only if meaningful risk exists
- Escalates to INCIDENT for OWASP A01 / A02
"""

import json
import os
import sys
from pathlib import Path
import urllib.request

# --------------------------------------------------
# Environment
# --------------------------------------------------
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL")
REPO = os.getenv("GITHUB_REPOSITORY", "unknown")
RUN_ID = os.getenv("GITHUB_RUN_ID", "manual")
PR = os.getenv("PR_NUMBER")

BASE = Path("security-reports")
ASVS = BASE / "governance/asvs-labels.json"
EPSS = BASE / "epss-findings.json"
ZAP = BASE / "zap/zap_alerts.json"
GATE = BASE / "gate_failed"

# --------------------------------------------------
# Helpers
# --------------------------------------------------
def load_json(path: Path) -> dict:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[WARN] Failed to load {path}: {e}")
    return {}

# --------------------------------------------------
# Main
# --------------------------------------------------
def main():
    if not SLACK_WEBHOOK:
        print("[SKIP] SLACK_WEBHOOK_URL not set")
        return

    asvs = load_json(ASVS)
    epss = load_json(EPSS)
    zap = load_json(ZAP)

    risk_labels = set(asvs.get("risk_labels", []))
    owasp_labels = set(asvs.get("owasp_labels", []))
    asvs_delta = asvs.get("asvs_delta", [])

    # --------------------------------------------------
    # EPSS summary
    # --------------------------------------------------
    high_risk = epss.get("high_risk", []) or []
    epss_max = 0.0
    for v in high_risk:
        try:
            epss_max = max(epss_max, float(v.get("epss", 0)))
        except Exception:
            pass

    # --------------------------------------------------
    # ZAP summary
    # --------------------------------------------------
    zap_counts = {}
    zap_high = 0

    for site in zap.get("site", []):
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc") or alert.get("risk") or "Unknown"
            zap_counts[risk] = zap_counts.get(risk, 0) + 1
            if str(alert.get("riskcode")) == "3":
                zap_high += 1

    # --------------------------------------------------
    # Decision logic
    # --------------------------------------------------
    gate_failed = GATE.exists()
    high_risk_flag = "risk:high" in risk_labels
    medium_risk_flag = "risk:medium" in risk_labels

    incident = any(
        o.startswith("OWASP-A01") or o.startswith("OWASP-A02")
        for o in owasp_labels
    )

    should_notify = (
        gate_failed
        or high_risk_flag
        or epss_max >= 0.5
        or zap_high > 0
        or asvs_delta
    )

    if not should_notify:
        print("[OK] No Slack notification required")
        return

    # --------------------------------------------------
    # Headline
    # --------------------------------------------------
    if gate_failed or incident:
        headline = "🚨 *SECURITY INCIDENT DETECTED*"
    elif high_risk_flag:
        headline = "🔴 *HIGH SECURITY RISK DETECTED*"
    elif medium_risk_flag:
        headline = "🟠 *MEDIUM SECURITY RISK DETECTED*"
    else:
        headline = "⚠️ *SECURITY SIGNAL DETECTED*"

    lines = [
        headline,
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
        lines.append("*ASVS Delta (New / Changed Controls):*")
        for a in asvs_delta[:8]:
            lines.append(f"• `{a}`")

    if owasp_labels:
        lines.append("")
        lines.append("*OWASP Top 10 Impact:*")
        for o in sorted(owasp_labels):
            lines.append(f"• `{o}`")

    # --------------------------------------------------
    # EPSS
    # --------------------------------------------------
    if high_risk:
        lines.append("")
        lines.append(f"*EPSS Max:* `{epss_max:.2f}`")
        for v in high_risk[:3]:
            reasons = ", ".join(v.get("reasons", []))
            lines.append(
                f"• `{v.get('cve')}` | EPSS `{float(v.get('epss',0)):.2f}` ({reasons})"
            )

    # --------------------------------------------------
    # ZAP
    # --------------------------------------------------
    if zap_counts:
        lines.append("")
        lines.append("*ZAP Alerts:*")
        for k, v in zap_counts.items():
            lines.append(f"• {k}: `{v}`")

    payload = {"text": "\n".join(lines)}

    # --------------------------------------------------
    # Send Slack
    # --------------------------------------------------
    req = urllib.request.Request(
        SLACK_WEBHOOK,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(req, timeout=10)
    print("[OK] Slack notification sent")

if __name__ == "__main__":
    main()
