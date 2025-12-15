#!/usr/bin/env python3
"""
Slack Notification – Governance Enriched (Level-Weighted Risk)

Consumes:
- security-reports/governance/asvs-coverage.json

Design:
- Slack = renderer only (NO recompute)
- Executive-readable
- Deterministic
"""

import json
import os
from pathlib import Path
import urllib.request
from typing import Dict, Any, List

# --------------------------------------------------
# Environment
# --------------------------------------------------
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL")
REPO = os.getenv("GITHUB_REPOSITORY", "unknown")
RUN_ID = os.getenv("GITHUB_RUN_ID", "manual")
PR = os.getenv("PR_NUMBER")

BASE = Path("security-reports")
ASVS = BASE / "governance/asvs-coverage.json"
GATE = BASE / "gate_failed"

TOP_FAILED = int(os.getenv("TOP_FAILED_ASVS", "5"))
TOP_FAMILIES = 3

# --------------------------------------------------
# Helpers
# --------------------------------------------------
def load_json(path: Path, default=None):
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[WARN] Failed to load {path}: {e}")
    return default if default is not None else {}

def send_slack(text: str):
    payload = {"text": text}
    req = urllib.request.Request(
        SLACK_WEBHOOK,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=10)

# --------------------------------------------------
# Slack formatting helpers
# --------------------------------------------------
def format_risk_block(risk: Dict[str, Any]) -> List[str]:
    lines = []
    lines.append("🔥 *Level-Weighted ASVS Risk*")
    lines.append(
        f"• Risk: `{risk.get('risk_percent', 0)}%` "
        f"(raw `{risk.get('raw_score', 0)}` / max `{risk.get('max_score', 0)}`)"
    )

    worst = risk.get("worst_families", [])[:TOP_FAMILIES]
    if worst:
        lines.append("• Worst domains:")
        for w in worst:
            lines.append(
                f"  - `{w['family']}`: `{w['risk_points']}` pts"
            )
    return lines

def format_failed_controls(controls: List[Dict[str, Any]]) -> List[str]:
    failed = [c for c in controls if c.get("status") == "FAIL"]
    failed = failed[:TOP_FAILED]

    if not failed:
        return []

    lines = []
    lines.append("❌ *Failed ASVS Controls*")
    for c in failed:
        owners = ", ".join(c.get("owners", [])) or "unknown"
        lines.append(
            f"• `{c['id']}` (L{c['level']}) – {c['title']}"
        )
        lines.append(f"  Owners: `{owners}`")
    return lines

# --------------------------------------------------
# Main
# --------------------------------------------------
def main():
    if not SLACK_WEBHOOK:
        print("[SKIP] SLACK_WEBHOOK_URL not set")
        return

    data = load_json(ASVS, {})
    summary = data.get("summary", {})
    risk = summary.get("risk", {})
    controls = data.get("controls", [])

    if not summary:
        print("[SKIP] No ASVS summary found")
        return

    gate_failed = GATE.exists()

    # --------------------------------------------------
    # Header
    # --------------------------------------------------
    lines = []
    if gate_failed:
        lines.append("🚨 *SECURITY GATE FAILED*")
    else:
        lines.append("⚠️ *SECURITY RISK UPDATE*")

    lines.append(f"*Repository:* `{REPO}`")
    lines.append(f"*Run ID:* `{RUN_ID}`")
    if PR:
        lines.append(f"*PR:* `#{PR}`")
    lines.append("")

    # --------------------------------------------------
    # Coverage
    # --------------------------------------------------
    lines.append("*ASVS Coverage:*")
    lines.append(
        f"• PASS `{summary.get('passed', 0)}` / "
        f"FAIL `{summary.get('failed', 0)}` "
        f"({summary.get('coverage_percent', 0)}%)"
    )

    # --------------------------------------------------
    # Risk block (🔥 core value)
    # --------------------------------------------------
    lines.append("")
    lines.extend(format_risk_block(risk))

    # --------------------------------------------------
    # Failed controls + owners
    # --------------------------------------------------
    failed_block = format_failed_controls(controls)
    if failed_block:
        lines.append("")
        lines.extend(failed_block)

    # --------------------------------------------------
    # Send Slack
    # --------------------------------------------------
    send_slack("\n".join(lines))
    print("[OK] Slack notification sent")

if __name__ == "__main__":
    main()
