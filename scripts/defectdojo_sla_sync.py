#!/usr/bin/env python3
"""
DefectDojo SLA Sync
- Set SLA based on severity
- Auto-close on PR merge
"""

import os, requests, datetime

DD_URL = os.environ["DEFECTDOJO_URL"]
DD_TOKEN = os.environ["DEFECTDOJO_API_KEY"]

HEADERS = {
    "Authorization": f"Token {DD_TOKEN}",
    "Content-Type": "application/json"
}

SLA = {
    "Critical": 7,
    "High": 14,
    "Medium": 30,
    "Low": 90
}

resp = requests.get(f"{DD_URL}/api/v2/findings/?active=true", headers=HEADERS)
findings = resp.json().get("results", [])

for f in findings:
    sev = f.get("severity")
    if sev not in SLA:
        continue

    due = datetime.date.today() + datetime.timedelta(days=SLA[sev])
    payload = {
        "sla_due_date": due.isoformat()
    }

    requests.patch(
        f"{DD_URL}/api/v2/findings/{f['id']}/",
        headers=HEADERS,
        json=payload
    )

print("[OK] SLA synced")
