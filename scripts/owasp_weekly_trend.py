#!/usr/bin/env python3
"""
Weekly OWASP Trend Report from PR Labels

- Queries merged PRs in the last 7 days
- Aggregates OWASP labels
- Writes owasp-weekly.json (dashboard & Slack ready)
"""

import os
import json
import datetime
import requests
from collections import Counter

GITHUB_API = "https://api.github.com"
REPO = os.getenv("GITHUB_REPOSITORY")
TOKEN = os.getenv("GITHUB_TOKEN")

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
}

def fetch_merged_prs():
    since = (datetime.datetime.utcnow() - datetime.timedelta(days=7)).isoformat() + "Z"
    url = f"{GITHUB_API}/repos/{REPO}/pulls?state=closed&per_page=100"
    prs = requests.get(url, headers=HEADERS, timeout=10).json()
    return [pr for pr in prs if pr.get("merged_at") and pr["merged_at"] >= since]

def main():
    prs = fetch_merged_prs()
    counter = Counter()

    for pr in prs:
        issue = requests.get(pr["issue_url"], headers=HEADERS, timeout=10).json()
        for l in issue.get("labels", []):
            name = l["name"]
            if name.startswith("OWASP-"):
                counter[name] += 1

    report = {
        "week": datetime.date.today().isoformat(),
        "total_prs": len(prs),
        "owasp_counts": dict(counter),
    }

    out = "security-reports/governance/owasp-weekly.json"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(report, open(out, "w"), indent=2)

    print("[OK] OWASP weekly trend generated")

if __name__ == "__main__":
    main()
