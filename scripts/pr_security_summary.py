#!/usr/bin/env python3
import json, os, sys

PR = os.getenv("GITHUB_EVENT_PATH")
REPO = os.getenv("GITHUB_REPOSITORY")
TOKEN = os.getenv("GITHUB_TOKEN")

epss_file = "security-reports/epss-findings.json"
asvs_file = "security-reports/governance/asvs-coverage.json"
gate_failed = os.path.exists("security-reports/gate_failed")

def load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default

epss = load(epss_file, {})
asvs = load(asvs_file, {})

high_risk = epss.get("high_risk", [])
threshold = epss.get("threshold", "N/A")

lines = []
lines.append("## 🔐 PR Security Summary")

if not high_risk:
    lines.append("✅ **No exploitable risks detected**")
else:
    lines.append(f"🚨 **High-risk findings (EPSS ≥ {threshold} / KEV)**")
    for v in high_risk[:5]:
        badge = "🟥" if v.get("is_kev") else "🟧"
        lines.append(
            f"- {badge} `{v['cve']}` "
            f"(EPSS {v['epss']}, CVSS {v.get('cvss','?')}) "
            f"– {', '.join(v['reasons'])}"
        )

if gate_failed:
    lines.append("\n❌ **PR BLOCKED by security gate**")
else:
    lines.append("\n✅ **Security gate passed**")

body = "\n".join(lines)

print(body)
