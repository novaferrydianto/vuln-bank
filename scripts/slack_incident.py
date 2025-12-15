#!/usr/bin/env python3
"""
Slack Incident Notifier – Critical OWASP

Triggers ONLY on confirmed incident-level risks.
This script must be:
- Deterministic
- Idempotent
- Escalation-only (no analysis)
"""

import os
import json
import urllib.request
from typing import List

# --------------------------------------------------
# Environment
# --------------------------------------------------
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL")
REPO = os.getenv("GITHUB_REPOSITORY", os.getenv("REPO", "unknown"))
RUN_ID = os.getenv("GITHUB_RUN_ID", "manual")
PR = os.getenv("PR_NUMBER")  # optional
OWASP_LABELS_RAW = os.getenv("OWASP_LABELS", "")

# --------------------------------------------------
# Constants
# --------------------------------------------------
INCIDENT_OWASP = {
    "OWASP-A01-Broken-Access-Control",
    "OWASP-A02-Broken-Authentication",
}

INCIDENT_CODE = "SEC-INC-OWASP-A01-A02"

# --------------------------------------------------
# Helpers
# --------------------------------------------------
def parse_labels(raw: str) -> List[str]:
    return [l.strip() for l in raw.split(",") if l.strip()]

def send_slack(payload: dict):
    req = urllib.request.Request(
        SLACK_WEBHOOK,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=10)

# --------------------------------------------------
# Main
# --------------------------------------------------
def main():
    if not SLACK_WEBHOOK:
        print("[SKIP] SLACK_WEBHOOK_URL not set")
        return

    labels = parse_labels(OWASP_LABELS_RAW)

    incident_labels = sorted(set(labels) & INCIDENT_OWASP)

    if not incident_labels:
        print("[OK] No incident-level OWASP detected")
        return

    # --------------------------------------------------
    # Payload (executive-grade, SOC-friendly)
    # --------------------------------------------------
    lines = [
        "🚨 *SECURITY INCIDENT DETECTED*",
        f"*Incident Code:* `{INCIDENT_CODE}`",
        f"*Repository:* `{REPO}`",
        f"*Run ID:* `{RUN_ID}`",
    ]

    if PR:
        lines.append(f"*PR:* `#{PR}`")

    lines.extend([
        "",
        "*Trigger (OWASP Top 10):*",
    ])

    for l in incident_labels:
        lines.append(f"• `{l}`")

    lines.extend([
        "",
        "*Severity:* `CRITICAL`",
        "*Action Required:* Immediate triage & containment",
    ])

    payload = {"text": "\n".join(lines)}

    send_slack(payload)
    print("[OK] Incident Slack notification sent")

if __name__ == "__main__":
    main()
