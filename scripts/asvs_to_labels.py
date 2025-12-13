#!/usr/bin/env python3
"""
ASVS → OWASP → GitHub PR Labels (Enterprise Governance)

Features:
- Delta-aware ASVS detection (baseline vs current)
- OWASP Top 10 mapping
- PR blocking on A01 / A02 introduction
- Risk tier labels (risk:high / medium / low)
- JSON export for trends & Slack
"""

import json
import os
import sys
import requests
from pathlib import Path
from typing import Dict, Set

# --------------------------------------------------
# Config
# --------------------------------------------------
ASVS_TO_OWASP = {
    "V1": "OWASP-A02-Broken-Authentication",
    "V2": "OWASP-A02-Broken-Authentication",
    "V3": "OWASP-A01-Broken-Access-Control",
    "V4": "OWASP-A03-Injection",
    "V5": "OWASP-A07-Identification-Auth-Failures",
    "V6": "OWASP-A02-Cryptographic-Failures",
    "V7": "OWASP-A05-Security-Misconfiguration",
    "V8": "OWASP-A08-Software-Integrity-Failures",
    "V9": "OWASP-A10-SSRF",
    "V10": "OWASP-A04-Insecure-Design",
    "V11": "OWASP-A04-Insecure-Design",
    "V12": "OWASP-A04-Insecure-Design",
    "V13": "OWASP-A04-Insecure-Design",
    "V14": "OWASP-A04-Insecure-Design",
}

BLOCK_OWASP = {
    "OWASP-A01-Broken-Access-Control",
    "OWASP-A02-Broken-Authentication",
}

RISK_TIERS = {
    "OWASP-A01-Broken-Access-Control": "risk:high",
    "OWASP-A02-Broken-Authentication": "risk:high",
    "OWASP-A03-Injection": "risk:medium",
    "OWASP-A05-Security-Misconfiguration": "risk:medium",
    "OWASP-A08-Software-Integrity-Failures": "risk:medium",
}

GITHUB_API = "https://api.github.com"

REPORT = Path("security-reports/governance/asvs-coverage.json")
BASELINE = Path("security-baselines/asvs-baseline.json")
EXPORT = Path("security-reports/governance/asvs-labels.json")

# --------------------------------------------------
# Helpers
# --------------------------------------------------
def load_json(path: Path) -> Dict:
    return json.loads(path.read_text()) if path.exists() else {}

def extract_chapters(d: Dict) -> Set[str]:
    return {k.split(".")[0] for k in d.get("counts", {}) if k.startswith("V")}

def map_owasp(chapters: Set[str]) -> Set[str]:
    return {ASVS_TO_OWASP[c] for c in chapters if c in ASVS_TO_OWASP}

def github_post_labels(repo, pr, token, labels):
    url = f"{GITHUB_API}/repos/{repo}/issues/{pr}/labels"
    r = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        json={"labels": sorted(labels)},
        timeout=10,
    )
    if r.status_code >= 300:
        print(f"[WARN] GitHub label API failed: {r.text}")

# --------------------------------------------------
# Main
# --------------------------------------------------
def main():
    repo = os.getenv("GITHUB_REPOSITORY")
    pr = os.getenv("PR_NUMBER")
    token = os.getenv("GITHUB_TOKEN")
    is_pr = all([repo, pr, token])

    current = load_json(REPORT)
    baseline = load_json(BASELINE)

    cur_ch = extract_chapters(current)
    base_ch = extract_chapters(baseline)

    delta_ch = cur_ch - base_ch
    delta_owasp = map_owasp(delta_ch)

    if not delta_owasp:
        print("[INFO] No new ASVS delta")
        return

    # --------------------------------------------------
    # Block PR on A01 / A02
    # --------------------------------------------------
    blocking = delta_owasp & BLOCK_OWASP
    if blocking:
        print("❌ BLOCKED: Critical OWASP introduced")
        for b in blocking:
            print(f" - {b}")
        Path("security-reports/gate_failed").write_text("ASVS/OWASP regression")
        sys.exit(1)

    # --------------------------------------------------
    # Risk tier labels
    # --------------------------------------------------
    risk_labels = {RISK_TIERS[o] for o in delta_owasp if o in RISK_TIERS}
    if not risk_labels:
        risk_labels.add("risk:low")

    final_labels = set(delta_owasp) | risk_labels

    # --------------------------------------------------
    # Export for Slack / Trend / Audit
    # --------------------------------------------------
    EXPORT.parent.mkdir(parents=True, exist_ok=True)
    EXPORT.write_text(json.dumps({
        "asvs_delta": sorted(delta_ch),
        "owasp_labels": sorted(delta_owasp),
        "risk_labels": sorted(risk_labels),
    }, indent=2))

    # --------------------------------------------------
    # Apply labels to PR
    # --------------------------------------------------
    if is_pr:
        github_post_labels(repo, pr, token, final_labels)
        print("[OK] Applied PR labels:")
        for l in sorted(final_labels):
            print(f" - {l}")

    # --------------------------------------------------
    # Auto-update baseline on main
    # --------------------------------------------------
    if os.getenv("GITHUB_REF") == "refs/heads/main":
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(json.dumps(current, indent=2))
        print("[OK] ASVS baseline updated (main)")

if __name__ == "__main__":
    main()
