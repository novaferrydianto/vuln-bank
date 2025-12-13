#!/usr/bin/env python3
import json, os
from pathlib import Path

REPORT_DIR = os.environ.get("REPORT_DIR", "security-reports")
EPSS_FILE = Path(REPORT_DIR) / "epss-findings.json"

data = {}
if EPSS_FILE.exists():
    data = json.load(open(EPSS_FILE))

high_risk = data.get("high_risk", [])
total = data.get("total_trivy_high_crit", 0)

should_notify = len(high_risk) > 0

summary = {
    "should_notify": should_notify,
    "total_trivy_high_crit": total,
    "high_risk_count": len(high_risk),
    "top_findings": high_risk[:5],
}

(Path(REPORT_DIR) / "notify_slack.json").write_text(
    json.dumps(summary, indent=2)
)

# GitHub output
gh = os.environ.get("GITHUB_OUTPUT")
if gh:
    with open(gh, "a") as f:
        f.write(f"should_notify={'true' if should_notify else 'false'}\n")

print(json.dumps(summary, indent=2))
