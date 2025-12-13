#!/usr/bin/env python3
"""
Sync GitHub PR risk → DefectDojo Engagement Risk Rating
"""

import os
import json
import requests

DD_URL = os.getenv("DEFECTDOJO_URL")
DD_KEY = os.getenv("DEFECTDOJO_API_KEY")
ENG_ID = os.getenv("DEFECTDOJO_ENGAGEMENT_ID")

ASVS_LABELS = "security-reports/governance/asvs-labels.json"

def main():
    if not ENG_ID:
        print("[SKIP] No engagement ID")
        return

    data = json.load(open(ASVS_LABELS))
    owasp = data.get("owasp_labels", [])
    risks = data.get("risk_labels", [])

    if any(a.startswith("OWASP-A01") or a.startswith("OWASP-A02") for a in owasp):
        rating = "Critical"
    elif "risk:high" in risks:
        rating = "High"
    elif "risk:medium" in risks:
        rating = "Medium"
    else:
        rating = "Low"

    resp = requests.patch(
        f"{DD_URL}/api/v2/engagements/{ENG_ID}/",
        headers={
            "Authorization": f"Token {DD_KEY}",
            "Content-Type": "application/json",
        },
        json={"risk_rating": rating},
        timeout=10,
    )

    if resp.status_code >= 300:
        print("[WARN] DefectDojo sync failed:", resp.text)
    else:
        print(f"[OK] DefectDojo risk set to {rating}")

if __name__ == "__main__":
    main()
