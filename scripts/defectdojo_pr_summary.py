#!/usr/bin/env python3
import os, requests

DD_URL = os.environ["DEFECTDOJO_URL"]
DD_TOKEN = os.environ["DEFECTDOJO_API_KEY"]
ENGAGEMENT_ID = os.environ["DEFECTDOJO_ENGAGEMENT_ID"]
REPO = os.environ["GITHUB_REPOSITORY"]
PR = os.environ["PR_NUMBER"]
GH_TOKEN = os.environ["GITHUB_TOKEN"]

headers = {"Authorization": f"Token {DD_TOKEN}"}

r = requests.get(
    f"{DD_URL}/api/v2/findings/?engagement={ENGAGEMENT_ID}&limit=500",
    headers=headers,
)
findings = r.json()["results"]

summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
for f in findings:
    summary[f["severity"]] += 1

comment = f"""### 🔐 Security Scan Summary (DefectDojo)

| Severity | Count |
|---------|-------|
| Critical | {summary['Critical']} |
| High | {summary['High']} |
| Medium | {summary['Medium']} |
| Low | {summary['Low']} |

Engagement ID: `{ENGAGEMENT_ID}`
"""

requests.post(
    f"https://api.github.com/repos/{REPO}/issues/{PR}/comments",
    headers={"Authorization": f"Bearer {GH_TOKEN}"},
    json={"body": comment},
)
