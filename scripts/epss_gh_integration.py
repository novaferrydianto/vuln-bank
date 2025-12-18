#!/usr/bin/env python3
"""
GitHub Integration for EPSS/KEV findings:
- Auto-PR Comment
- Auto-create Issues
- Auto-assign
- Auto-label severity
- Auto-close resolved issues

Refactored to reduce Cognitive Complexity (<15).
"""

import json
import os
import sys
import subprocess
from typing import List, Dict, Any


EPSS_FILE = os.environ.get("EPSS_FINDINGS", "security-reports/epss-findings.json")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
REPO = os.environ.get("GITHUB_REPOSITORY", "")


# ================================================
# Helpers
# ================================================
def load_epss_findings(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {"high_risk": []}

    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {"high_risk": []}


def gh_api(args: List[str], payload: dict | None = None) -> None:
    """Wrapper for gh CLI calls."""
    base = ["gh"] + args + ["--repo", REPO]
    if payload:
        proc = subprocess.Popen(
            base, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        proc.communicate(json.dumps(payload).encode("utf-8"))
    else:
        subprocess.run(base, check=False)


# ================================================
# Rendering
# ================================================
def format_pr_comment(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "### EPSS / KEV\nNo high-risk vulnerabilities detected."

    lines = ["### EPSS High-Risk CVEs Detected", ""]
    for item in findings:
        lines.append(
            f"- **{item['cve']}** | EPSS={item['epss']} "
            f"| KEV={item.get('is_kev', False)} "
            f"| Severity={item.get('severity', 'N/A')}"
        )
    return "\n".join(lines)


def map_severity_tag(sev: str) -> str:
    mapping = {
        "CRITICAL": "severity-critical",
        "HIGH": "severity-high",
        "MEDIUM": "severity-medium",
        "LOW": "severity-low",
    }
    return mapping.get(sev.upper(), "severity-unknown")


# ================================================
# Issue Management
# ================================================
def create_issue(item: Dict[str, Any]) -> None:
    title = f"[EPSS] {item['cve']} – High-Risk Vulnerability"
    body = (
        f"EPSS Score: **{item['epss']}**\n"
        f"KEV: **{item.get('is_kev', False)}**\n"
        f"Severity: **{item['severity']}**\n"
        f"CVSS: **{item.get('cvss', 'N/A')}**\n"
        f"Package: **{item.get('pkg_name', '-') }**\n"
        f"Installed: **{item.get('installed_version', '-') }**\n"
        f"Fixed: **{item.get('fixed_version', '-') }**\n"
    )

    labels = [
        "EPSS",
        map_severity_tag(item.get("severity", "")),
        "needs-triage",
    ]
    payload = {
        "title": title,
        "body": body,
        "labels": labels,
        "assignees": ["novaferrydianto"],
    }
    gh_api(["issue", "create"], payload)


def close_obsolete_issues(existing: List[str], active: List[str]) -> None:
    """Close issues whose CVEs are no longer high-risk."""
    obsolete = set(existing) - set(active)
    for cve in obsolete:
        gh_api(["issue", "close", "--reason", "completed", "--title", f"[EPSS] {cve}"])


def list_existing_epss_issues() -> List[str]:
    """Fetch titles of existing EPSS issues."""
    proc = subprocess.Popen(
        [
            "gh",
            "issue",
            "list",
            "--search",
            "EPSS",
            "--json",
            "title",
            "--repo",
            REPO,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, _ = proc.communicate()

    try:
        items = json.loads(out.decode("utf-8"))
        return [i["title"].split()[1] for i in items if i["title"].startswith("[EPSS]")]
    except Exception:
        return []


# ================================================
# PR Comment
# ================================================
def post_pr_comment(findings: List[Dict[str, Any]]) -> None:
    if not os.environ.get("GITHUB_REF", "").startswith("refs/pull/"):
        return

    comment = format_pr_comment(findings)
    gh_api(["pr", "comment"], {"body": comment})


# ================================================
# Main
# ================================================
def main() -> None:
    data = load_epss_findings(EPSS_FILE)
    findings = data.get("high_risk", [])

    # PR Auto-comment
    post_pr_comment(findings)

    # Issue sync
    existing = list_existing_epss_issues()
    active = [i["cve"] for i in findings]

    for item in findings:
        if item["cve"] not in existing:
            create_issue(item)

    close_obsolete_issues(existing, active)


if __name__ == "__main__":
    main()
