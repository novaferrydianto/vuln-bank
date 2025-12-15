import json
import os
import requests

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
REPO = os.environ["GITHUB_REPOSITORY"]

epss = json.loads(open("security-reports/epss-findings.json").read())

headers = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
}

for v in epss.get("high_risk", []):
    if not v.get("is_kev"):
        continue

    title = f"[KEV] {v['cve']} exploitable vulnerability"
    body = f"""
**CVE:** {v['cve']}
**Package:** {v['pkg_name']}
**Installed:** {v['installed_version']}
**EPSS:** {v['epss']}
**CISA KEV:** YES

Detected automatically by CI.
"""

    requests.post(
        f"https://api.github.com/repos/{REPO}/issues",
        headers=headers,
        json={
            "title": title,
            "body": body,
            "labels": ["security", "kev", "urgent"],
        },
    )
