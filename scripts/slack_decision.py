#!/usr/bin/env python3
"""
Slack Notification – Governance Enriched (Enterprise)

Signals:
- Gate decision
- ASVS PASS% + delta
- Failed ASVS controls (top-N)
- ASCII sparkline fallback
- EPSS / KEV high-risk correlation
- ZAP severity summary

Design goals:
- Explainable security decision
- Executive-readable
- PR & main safe
"""

import json
import os
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

ASVS_LABELS = BASE / "governance/asvs-labels.json"
ASVS_COVERAGE = BASE / "governance/asvs-coverage.json"
PASS_TREND = Path("security-metrics/weekly/pass-trend.json")

EPSS = BASE / "epss-findings.json"
ZAP = BASE / "zap/zap_alerts.json"
GATE = BASE / "gate_failed"

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

def ascii_sparkline(values):
    if not values:
        return "n/a"

    blocks = "▁▂▃▄▅▆▇█"
    mn, mx = min(values), max(values)
    if mx == mn:
        return blocks[4] * len(values)

    return "".join(
        blocks[int((v - mn) / (mx - mn) * (len(blocks) - 1))]
        for v in values
    )

# --------------------------------------------------
# ASVS helpers
# --------------------------------------------------
def load_failed_asvs(limit=5):
    data = load_json(ASVS_COVERAGE)
    failed = [
        c for c in data.get("controls", [])
        if c.get("status") == "FAIL"
    ]
    return failed[:limit]

def load_pass_metrics():
    data = load_json(ASVS_COVERAGE)
    summary = data.get("summary", {})

    pass_pct = summary.get("pass_percent")

    trend = load_json(PASS_TREND, {}).get("points", [])
    last = trend[-1]["pass_percent"] if len(trend) >= 1 else None
    prev = trend[-2]["pass_percent"] if len(trend) >= 2 else None

    delta = None
    if last is not None and prev is not None:
        delta = round(last - prev, 2)

    spark = ascii_sparkline(
        [p["pass_percent"] for p in trend[-8:]]
    )

    return pass_pct, delta, spark

# --------------------------------------------------
# Main
# --------------------------------------------------
def main():
    if not SLACK_WEBHOOK:
        print("[SKIP] SLACK_WEBHOOK_URL not set")
        return

    asvs_labels = load_json(ASVS_LABELS)
    epss = load_json(EPSS)
    zap = load_json(ZAP)

    risk_labels = set(asvs_labels.get("risk_labels", []))
    owasp_labels = set(asvs_labels.get("owasp_labels", []))
    asvs_delta = asvs_labels.get("asvs_delta", [])

    # --------------------------------------------------
    # EPSS / KEV summary
    # --------------------------------------------------
    high_risk = epss.get("high_risk", []) or []
    epss_max = max(
        (float(v.get("epss", 0)) for v in high_risk),
        default=0.0
    )

    kev_count = sum(1 for v in high_risk if v.get("kev"))

    # --------------------------------------------------
    # ZAP summary
    # --------------------------------------------------
    zap_high = 0
    zap_counts = {}

    for site in zap.get("site", []):
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc") or "Unknown"
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
        or kev_count > 0
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
    # PASS% + trend
    # --------------------------------------------------
    pass_pct, delta, spark = load_pass_metrics()
    if pass_pct is not None:
        delta_txt = f"{'▲' if delta > 0 else '▼'} {delta}%" if delta is not None else "n/a"
        lines.extend([
            "*ASVS PASS%:*",
            f"• Current: `{pass_pct}%` ({delta_txt})",
            f"• Trend: `{spark}`",
        ])

    # --------------------------------------------------
    # Failed ASVS controls
    # --------------------------------------------------
    failed = load_failed_asvs()
    if failed:
        lines.append("")
        lines.append("*❌ Failed ASVS Controls:*")
        for c in failed:
            lines.append(
                f"• `{c['id']}` ({c['level']}) – {c['title']}"
            )

    # --------------------------------------------------
    # OWASP
    # --------------------------------------------------
    if owasp_labels:
        lines.append("")
        lines.append("*OWASP Top 10 Impact:*")
        for o in sorted(owasp_labels):
            lines.append(f"• `{o}`")

    # --------------------------------------------------
    # EPSS / KEV
    # --------------------------------------------------
    if high_risk:
        lines.append("")
        lines.append(f"*EPSS Max:* `{epss_max:.2f}` | *KEV:* `{kev_count}`")
        for v in high_risk[:3]:
            lines.append(
                f"• `{v.get('cve')}` | EPSS `{float(v.get('epss',0)):.2f}`"
            )

    # --------------------------------------------------
    # ZAP
    # --------------------------------------------------
    if zap_counts:
        lines.append("")
        lines.append("*ZAP Alerts:*")
        for k, v in zap_counts.items():
            lines.append(f"• {k}: `{v}`")

    # --------------------------------------------------
    # Send Slack
    # --------------------------------------------------
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
