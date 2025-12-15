#!/usr/bin/env python3
"""
Merge Freeze Gate

Fails if there is any OPEN security incident.
"""

import os
import json
import urllib.request

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO = os.getenv("GITHUB_REPOSITORY")
API = f"https://api.github.com/repos/{REPO}"

HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
}

def main():
    req = urllib.request.Request(
        f"{API}/issues?state=open&labels=security-incident",
        headers=HEADERS,
    )
    with urllib.request.urlopen(req) as r:
        issues = json.loads(r.read())

    if issues:
        print("🚫 Merge frozen: open security incident exists")
        exit(1)

    print("✅ No open incidents. Merge allowed.")

if __name__ == "__main__":
    main()
