#!/usr/bin/env python3
import os, requests, json

LABEL_TO_RISK = {
    "risk:high": "Critical",
    "risk:medium": "High",
    "risk:low": "Medium",
}

dd_url = os.environ["DEFECTDOJO_URL"]
token = os.environ["DEFECTDOJO_API_KEY"]
engagement = os.environ["DEFECTDOJO_ENGAGEMENT_ID"]
labels = json.loads(os.environ["PR_LABELS"])

risk = "Low"
for l in labels:
    if l in LABEL_TO_RISK:
        risk = LABEL_TO_RISK[l]
        break

payload = {"risk_acceptance": False, "risk_rating": risk}

r = requests.patch(
    f"{dd_url}/api/v2/engagements/{engagement}/",
    headers={
        "Authorization": f"Token {token}",
        "Content-Type": "application/json",
    },
    json=payload,
    timeout=10,
)

print(f"[OK] DefectDojo risk set to {risk}")
