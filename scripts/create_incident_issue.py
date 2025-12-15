#!/usr/bin/env python3
"""
Auto-create GitHub Security Incident Issue

Idempotent:
- If an open incident exists → reuse
- Else → create new
"""

import os
import json
import urllib.request
import urllib.error

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO = os.getenv("GITHUB_REPOSITORY")
RUN_ID = os.getenv("GITHUB_RUN_ID", "manual")
PR = os.getenv("PR_NUMBER")
OWASP_LABELS = os.getenv("OWASP_LABELS", "")
API = f"https://api.github.com/repos/{REPO}"

HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
}

INCIDENT_LABEL = "security-incident"
FREEZE_LABEL = "freeze-merge"

def request(method, url, payload=None):
    data = json.dumps(payload).encode() if payload else None
    req = urllib.request.Request(url, data=data, headers=HEADERS, method=method)
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

def find_open_incident():
    issues = request(
        "GET",
        f"{API}/issues?state=open&labels={INCIDENT_LABEL}"
    )
    return issues[0] if issues else None

def create_incident():
    title = "🚨 Security Incident – OWASP A01/A02"
    body = f"""
## 🚨 Security Incident

**Detected by CI pipeline**

- Repo: `{REPO}`
- Run ID: `{RUN_ID}`
- PR: `{PR or 'n/a'}`
- OWASP: {OWASP_LABELS}

### Required Actions
- Root cause analysis
- Patch & validate
- Close this issue to unfreeze merges
"""

    return request(
        "POST",
        f"{API}/issues",
        {
            "title": title,
            "body": body,
            "labels": [INCIDENT_LABEL, FREEZE_LABEL],
        }
    )

def main():
    if not GITHUB_TOKEN:
        raise RuntimeError("GITHUB_TOKEN not set")

    incident = find_open_incident()
    if incident:
        print(f"[OK] Existing incident issue found: #{incident['number']}")
        return

    issue = create_incident()
    print(f"[OK] Incident issue created: #{issue['number']}")

if __name__ == "__main__":
    main()
