#!/usr/bin/env python3
import os, json, requests

REPO = os.getenv("REPO")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
EPSS_FILE = os.getenv("EPSS_FILE")
SNYK_FILE = os.getenv("SNYK_FILE")

API_URL = f"https://api.github.com/repos/{REPO}/issues"
HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json"
}

def load_existing_issue_titles():
    """Load ALL issue titles (open & closed) to avoid duplicates."""
    titles = set()

    for state in ["open", "closed"]:
        resp = requests.get(API_URL, headers=HEADERS, params={"state": state})
        if resp.status_code == 200:
            for issue in resp.json():
                titles.add(issue["title"])

    return titles

EXISTING_TITLES = load_existing_issue_titles()


def create_issue(title, body, labels):
    if title in EXISTING_TITLES:
        print(f"[SKIP] Already exists: {title}")
        return

    payload = {"title": title, "body": body, "labels": labels}

    r = requests.post(API_URL, headers=HEADERS, json=payload)
    if r.status_code >= 300:
        print("[ERROR] Could not create issue:", r.text)
    else:
        print("[OK] Created:", title)
        EXISTING_TITLES.add(title)


# ==============================================================
# SNYK SECTION (SCA)
# ==============================================================

def process_snyk():
    if not os.path.exists(SNYK_FILE):
        print("[INFO] No Snyk file found")
        return

    data = json.load(open(SNYK_FILE))
    vulns = data.get("vulnerabilities", [])

    seen = set()

    for v in vulns:
        cve = v.get("id")
        pkg = v.get("packageName")
        severity = v.get("severity", "").upper()

        if not cve or not pkg:
            continue

        # Dedup by CVE + package
        key = f"{cve}:{pkg}"
        if key in seen:
            continue
        seen.add(key)

        title = f"[Snyk {severity}] {cve} in {pkg}"

        body = f"""
## Snyk Vulnerability
- Package: **{pkg}**
- Severity: **{severity}**
- ID: **{cve}**
- URL: {v.get("url")}
"""

        labels = ["auto-created", "security", "sca", severity.lower()]
        create_issue(title, body, labels)


# ==============================================================
# EPSS SECTION
# ==============================================================

def process_epss():
    if not os.path.exists(EPSS_FILE):
        print("[INFO] No EPSS file found")
        return

    data = json.load(open(EPSS_FILE))
    vulns = data.get("high_risk", [])

    seen = set()

    for v in vulns:
        cve = v.get("cve")
        if not cve:
            continue

        if cve in seen:
            continue
        seen.add(cve)

        epss = v.get("epss")
        percentile = v.get("percentile")
        reasons = ", ".join(v.get("reasons", []))

        title = f"[CVE HIGH] EPSS High-Risk Vulnerability {cve}"

        body = f"""
## EPSS High-Risk CVE
- CVE: **{cve}**
- EPSS Score: **{epss}**
- Percentile: **{percentile}**
- Reasons: {reasons}
"""

        labels = ["security", "severity-high", "epss"]
        create_issue(title, body, labels)


# ==============================================================
# MAIN
# ==============================================================

if __name__ == "__main__":
    process_epss()
    process_snyk()
