#!/usr/bin/env python3
import os
import json
import argparse
import requests

API = "https://api.github.com"


# -------------------------------------------------------------------
# HTTP Helpers
# -------------------------------------------------------------------
def gh_get(url, token):
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
    if r.status_code == 200:
        return r.json()
    return None


def gh_post(url, token, payload):
    r = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json"
        },
        json=payload,
    )
    return r.json(), r.status_code


def gh_patch(url, token, payload):
    r = requests.patch(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json"
        },
        json=payload,
    )
    return r.json(), r.status_code


# -------------------------------------------------------------------
# FIND EXISTING ISSUE (by CVE)
# -------------------------------------------------------------------
def find_existing_issue(owner, repo, token, cve):
    issues_url = f"{API}/repos/{owner}/{repo}/issues?state=open&per_page=100"
    issues = gh_get(issues_url, token) or []

    for issue in issues:
        if cve in issue.get("title", ""):
            return issue

    return None


# -------------------------------------------------------------------
# CREATE ISSUE
# -------------------------------------------------------------------
def create_issue(owner, repo, token, item):
    cve = item["cve"]
    severity = item["severity"]
    epss = item["epss"]
    pkg = item.get("pkg")
    version = item.get("version")
    is_kev = item.get("is_kev")

    title = f"[Security] {cve} — {severity} — EPSS {epss:.2f}"

    labels = [
        "security",
        f"severity:{severity.lower()}",
        f"source:{item.get('source', 'unknown')}"
    ]

    if epss >= 0.5:
        labels.append("epss-high")
    if is_kev:
        labels.append("kev")

    body = f"""
## CVE Details
**CVE:** {cve}  
**Severity:** {severity}  
**Package:** `{pkg}`  
**Installed Version:** `{version}`  

### EPSS
- Score: **{epss:.2f}**
- Percentile: **{item.get('percentile', 0):.2f}**

### Flags
- EPSS >= threshold: `{epss >= 0.5}`
- CISA KEV: `{is_kev}`

---

Created automatically by *Vuln Bank DevSecOps Pipeline*.
"""

    url = f"{API}/repos/{owner}/{repo}/issues"

    return gh_post(url, token, {"title": title, "body": body, "labels": labels})


# -------------------------------------------------------------------
# UPDATE ISSUE (severity/epss changed)
# -------------------------------------------------------------------
def update_issue(issue, token, item):
    epss = item["epss"]
    severity = item["severity"]

    updated_body = (
        issue.get("body", "") +
        f"\n\n### 🔄 Update via DevSecOps pipeline\n"
        f"- Severity: {severity}\n"
        f"- EPSS: {epss:.2f}\n"
        f"- KEV: {item.get('is_kev')}\n"
    )

    return gh_patch(issue["url"], token, {"body": updated_body})


# -------------------------------------------------------------------
# AUTO-CLOSE FIXED ISSUES
# -------------------------------------------------------------------
def auto_close_fixed(owner, repo, token, high_risk):
    print("Checking for CVEs that have been fixed...")

    issues_url = f"{API}/repos/{owner}/{repo}/issues?state=open&per_page=100"
    current_issues = gh_get(issues_url, token) or []

    high_risk_cves = {item["cve"] for item in high_risk}

    for issue in current_issues:
        title = issue.get("title", "")

        if "[Security]" not in title:
            continue

        parts = title.split()
        cve_candidates = [p for p in parts if p.startswith("CVE-")]
        if not cve_candidates:
            continue

        issue_cve = cve_candidates[0]

        # If no longer detected → auto-close
        if issue_cve not in high_risk_cves:
            print(f"[AUTO-CLOSE] CVE resolved: {issue_cve}")

            # Close issue
            gh_patch(issue["url"], token, {"state": "closed"})

            # Add comment
            gh_post(issue["comments_url"], token, {
                "body": (
                    f"✔️ This vulnerability appears to be fixed and is no longer detected "
                    f"in the latest security scans.\n"
                    f"Automatically closed by Vuln Bank DevSecOps Pipeline."
                )
            })

            # Add label
            existing_labels = [lbl["name"] for lbl in issue.get("labels", [])]
            if "auto-closed" not in existing_labels:
                updated_labels = existing_labels + ["auto-closed"]
                gh_patch(issue["url"], token, {"labels": updated_labels})


# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="GitHub Issues Auto-Creator")
    parser.add_argument("--repo", required=True, help="e.g. novaferrydianto/vuln-bank")
    parser.add_argument("--epss", required=True, help="epss-findings.json")
    args = parser.parse_args()

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise SystemExit("Missing GITHUB_TOKEN")

    owner, repo = args.repo.split("/")
    data = json.load(open(args.epss))
    high_risk = data.get("high_risk", [])

    # -------------------------------------------------------------------
    # CREATE OR UPDATE ISSUES
    # -------------------------------------------------------------------
    for item in high_risk:
        cve = item["cve"]
        existing = find_existing_issue(owner, repo, token, cve)

        if existing:
            print(f"[UPDATE] Existing issue updated for {cve}")
            update_issue(existing, token, item)
        else:
            print(f"[CREATE] New issue created for {cve}")
            create_issue(owner, repo, token, item)

    # -------------------------------------------------------------------
    # AUTO-CLOSE IF FIXED
    # -------------------------------------------------------------------
    auto_close_fixed(owner, repo, token, high_risk)


# -------------------------------------------------------------------
if __name__ == "__main__":
    main()
