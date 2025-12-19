#!/usr/bin/env python3
import os, json, sys
from urllib import request, parse

token = os.environ["GITHUB_TOKEN"]
repo  = os.environ.get("REPO")

epss_file   = os.environ.get("EPSS_FILE", "security-reports/epss-findings.json")
snyk_sca    = os.environ.get("SNYK_SCA", "security-reports/snyk/snyk-sca.json")

API = f"https://api.github.com/repos/{repo}/issues"
HEADERS = {
    "Authorization": f"token {token}",
    "Accept": "application/vnd.github+json",
    "User-Agent": "vuln-bank-epxs-bot"
}

def create_issue(title, body, labels):
    data = json.dumps({"title": title, "body": body, "labels": labels}).encode()
    req = request.Request(API, data=data, headers=HEADERS, method="POST")
    with request.urlopen(req) as resp:
        print("Created issue:", resp.status)

def main():
    # EPSS high_risk
    if os.path.isfile(epss_file):
        with open(epss_file) as f:
            epss = json.load(f)
        for item in epss.get("high_risk", []):
            title = f"[EPSS HIGH] {item['cve']} on {item['pkg_name']}"
            body  = (
                f"* CVE: {item['cve']}\n"
                f"* Package: {item['pkg_name']} {item['installed_version']}\n"
                f"* Severity: {item['severity']}\n"
                f"* CVSS: {item.get('cvss')}\n"
                f"* EPSS: {item.get('epss')} (percentile {item.get('percentile')})\n"
                f"* Reasons: {', '.join(item.get('reasons', []))}\n"
            )
            labels = ["security", "EPSS-high", "auto-created"]
            create_issue(title, body, labels)

    # Snyk SCA high/critical
    if os.path.isfile(snyk_sca):
        with open(snyk_sca) as f:
            snyk = json.load(f)
        for v in snyk.get("vulnerabilities", []):
            if v.get("severity") not in ("high", "critical"):
                continue
            title = f"[Snyk {v['severity'].upper()}] {v['id']} in {v['packageName']}"
            body  = (
                f"* ID: {v['id']}\n"
                f"* Package: {v['packageName']} {v.get('version')}\n"
                f"* Severity: {v['severity']}\n"
                f"* CVSS: {v.get('cvssScore')}\n"
                f"* URL: {v.get('url')}\n"
            )
            labels = ["security", "SCA", v["severity"], "auto-created"]
            create_issue(title, body, labels)

if __name__ == "__main__":
    main()
