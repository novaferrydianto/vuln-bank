#!/usr/bin/env python3
"""
Weekly OWASP Trend
- Pull merged PR labels from last 7 days
- Aggregate OWASP Top 10 counts
- Output JSON + HTML-ready data
"""

import os, json, requests, datetime

REPO = os.environ["GITHUB_REPOSITORY"]
TOKEN = os.environ["GITHUB_TOKEN"]

since = (datetime.datetime.utcnow() - datetime.timedelta(days=7)).isoformat() + "Z"

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json"
}

url = f"https://api.github.com/repos/{REPO}/pulls?state=closed&per_page=100"

resp = requests.get(url, headers=headers, timeout=30)
prs = resp.json()

trend = {f"A{str(i).zfill(2)}": 0 for i in range(1, 11)}

for pr in prs:
    if not pr.get("merged_at"):
        continue
    if pr["merged_at"] < since:
        continue

    labels = [l["name"] for l in pr.get("labels", [])]
    for l in labels:
        if l.startswith("OWASP-A"):
            key = l.split("-")[1]
            trend[key] += 1

out = {
    "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
    "window": "7d",
    "trend": trend
}

os.makedirs("docs/data", exist_ok=True)
json.dump(out, open("docs/data/owasp-weekly.json", "w"), indent=2)

print("[OK] Weekly OWASP trend generated")
