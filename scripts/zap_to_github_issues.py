#!/usr/bin/env python3
"""
ZAP → GitHub Issues Integrator (FINAL)

Features:
- Create GitHub Issues from OWASP ZAP findings
- Ignore alerts via zap_ignore_alerts.json
- Auto-close resolved issues
- Idempotent (safe for CI re-runs)
- SLA / severity labels
- Dashboard cross-link

Required env:
- GITHUB_TOKEN
- GITHUB_REPOSITORY (owner/repo)

Expected files:
- security-reports/zap/zap_alerts.json
- zap_ignore_alerts.json (optional)
"""

import json
import os
import sys
import requests
from pathlib import Path
from typing import Dict, List, Set

# ---------------------------------------------------------
# Config
# ---------------------------------------------------------
ZAP_JSON = Path("security-reports/zap/zap_alerts.json")
IGNORE_ALERTS_FILE = Path("zap_ignore_alerts.json")

GITHUB_API = "https://api.github.com"
REPO = os.getenv("GITHUB_REPOSITORY")
TOKEN = os.getenv("GITHUB_TOKEN")

DASHBOARD_URL = (
    f"https://{REPO.split('/')[0]}.github.io/{REPO.split('/')[1]}"
    if REPO else ""
)

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
}

SEVERITY_MAP = {
    "High": "CRITICAL",
    "Medium": "HIGH",
    "Low": "MEDIUM",
    "Informational": "LOW",
}

SLA_LABELS = {
    "CRITICAL": "sla-7-days",
    "HIGH": "sla-14-days",
    "MEDIUM": "sla-30-days",
    "LOW": "sla-90-days",
}

BASE_LABELS = ["security", "dast", "zap"]

# ---------------------------------------------------------
# Utilities
# ---------------------------------------------------------
def fatal(msg: str):
    print(f"[FATAL] {msg}")
    sys.exit(1)


def load_ignored_alerts() -> Set[str]:
    if not IGNORE_ALERTS_FILE.exists():
        return set()
    try:
        data = json.loads(IGNORE_ALERTS_FILE.read_text())
        return {str(x).strip() for x in data if str(x).strip()}
    except Exception as e:
        print(f"[WARN] Failed loading zap_ignore_alerts.json: {e}")
        return set()


# ---------------------------------------------------------
# ZAP Parsing
# ---------------------------------------------------------
def parse_zap_findings(zap_data: Dict, ignored: Set[str]) -> Dict[str, Dict]:
    """
    Returns:
      key -> finding
      key = alert|uri
    """
    findings = {}

    for site in zap_data.get("site", []):
        for alert in site.get("alerts", []):
            title = (alert.get("alert") or "").strip()
            if not title:
                continue

            if title in ignored:
                print(f"[IGNORE] {title}")
                continue

            risk = alert.get("risk", "Low")
            severity = SEVERITY_MAP.get(risk, "LOW")

            for inst in alert.get("instances", []):
                uri = inst.get("uri")
                if not uri:
                    continue

                key = f"{title}|{uri}"

                findings[key] = {
                    "title": title,
                    "uri": uri,
                    "risk": risk,
                    "severity": severity,
                    "description": alert.get("description", ""),
                    "solution": alert.get("solution", ""),
                    "reference": alert.get("reference", ""),
                }

    return findings


# ---------------------------------------------------------
# GitHub API
# ---------------------------------------------------------
def github_get(url, params=None):
    r = requests.get(url, headers=HEADERS, params=params)
    r.raise_for_status()
    return r.json()


def github_post(url, payload):
    r = requests.post(url, headers=HEADERS, json=payload)
    r.raise_for_status()
    return r.json()


def github_patch(url, payload):
    r = requests.patch(url, headers=HEADERS, json=payload)
    r.raise_for_status()
    return r.json()


def get_open_dast_issues() -> List[Dict]:
    issues = github_get(
        f"{GITHUB_API}/repos/{REPO}/issues",
        params={"state": "open", "per_page": 100},
    )

    result = []
    for i in issues:
        labels = [l["name"] for l in i.get("labels", [])]
        if (
            i["title"].startswith("[DAST]")
            and "dast" in labels
            and "do-not-close" not in labels
            and "risk-accepted" not in labels
        ):
            result.append(i)
    return result


def extract_issue_keys(issue: Dict) -> Set[str]:
    keys = set()
    title = issue["title"].split("] ", 1)[-1]
    for line in issue.get("body", "").splitlines():
        if line.startswith("- http"):
            keys.add(f"{title}|{line[2:].strip()}")
    return keys


# ---------------------------------------------------------
# Issue Management
# ---------------------------------------------------------
def create_issue(finding: Dict):
    title = f"[DAST] {finding['title']}"
    labels = BASE_LABELS + [
        f"severity/{finding['severity']}",
        SLA_LABELS.get(finding["severity"], "sla-30-days"),
    ]

    body = f"""
### 🔍 DAST Finding (OWASP ZAP)

**URL:**  
- {finding['uri']}

**Severity:** `{finding['severity']}`  
**Risk:** `{finding['risk']}`

---

### 📖 Description
{finding['description']}

---

### 🛠️ Recommended Fix
{finding['solution']}

---

### 🔗 References
{finding['reference']}

---

📊 **Security Dashboard:**  
{DASHBOARD_URL}

_This issue is automatically managed by the DevSecOps pipeline._
"""

    payload = {
        "title": title,
        "body": body.strip(),
        "labels": labels,
    }

    github_post(f"{GITHUB_API}/repos/{REPO}/issues", payload)
    print(f"[CREATE] {title}")


def close_issue(issue: Dict, reason: str):
    github_patch(
        f"{GITHUB_API}/repos/{REPO}/issues/{issue['number']}",
        {"state": "closed"},
    )

    comment = {
        "body": f"""
✅ **Auto-closed by DevSecOps pipeline**

**Reason:** {reason}

The latest OWASP ZAP scan no longer reports this finding.

📊 Dashboard: {DASHBOARD_URL}
"""
    }

    github_post(
        f"{GITHUB_API}/repos/{REPO}/issues/{issue['number']}/comments",
        comment,
    )

    print(f"[CLOSE] Issue #{issue['number']} closed")


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------
def main():
    if not TOKEN or not REPO:
        fatal("GITHUB_TOKEN or GITHUB_REPOSITORY not set")

    if not ZAP_JSON.exists():
        print("[INFO] No ZAP results found")
        return

    ignored = load_ignored_alerts()
    if ignored:
        print(f"[INFO] Loaded {len(ignored)} ignored alerts")

    zap_data = json.loads(ZAP_JSON.read_text())
    current_findings = parse_zap_findings(zap_data, ignored)

    open_issues = get_open_dast_issues()
    open_issue_keys = {}

    for issue in open_issues:
        for k in extract_issue_keys(issue):
            open_issue_keys[k] = issue

    # Create new issues
    for key, finding in current_findings.items():
        if key not in open_issue_keys:
            create_issue(finding)

    # Auto-close resolved
    closed = 0
    for issue in open_issues:
        issue_keys = extract_issue_keys(issue)
        if issue_keys and issue_keys.isdisjoint(current_findings.keys()):
            close_issue(issue, "Finding no longer detected by ZAP")
            closed += 1

    print(f"[OK] ZAP sync complete | Auto-closed: {closed}")


if __name__ == "__main__":
    main()
