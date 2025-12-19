#!/usr/bin/env python3
"""
Enterprise Slack Notifier (Threaded Version, 2025)
--------------------------------------------------
- Posts a primary "Security Gate Result" message
- Sends scanner-specific detail replies in the thread
- SonarQube-clean: reduces cognitive complexity by decomposition
- Ruff-clean: no unused vars, minimal nesting, safe JSON loader
"""

import os
import json
import requests
from typing import Any, Dict, List


# ============================================================
# Utility Functions
# ============================================================

def load_json(path: str) -> Any:
    """Load JSON safely; return None if invalid."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def slack_post(token: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """POST to Slack chat.postMessage."""
    url = "https://slack.com/api/chat.postMessage"
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": f"Bearer {token}",
    }
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        parsed = response.json()
        if not parsed.get("ok"):
            print(f"[WARN] Slack error: {parsed}")
        return parsed
    except Exception as exc:
        print(f"[ERROR] Slack network failure: {exc}")
        return {}


def slack_field(title: str, value: Any) -> Dict[str, Any]:
    """Slack field helper."""
    return {"type": "mrkdwn", "text": f"*{title}:*\n{value}"}


def count_items(data: Any, predicate) -> int:
    """Count list items that satisfy a predicate."""
    if not isinstance(data, list):
        return 0
    return sum(1 for item in data if predicate(item))


# ============================================================
# Scanner-specific extraction helpers
# ============================================================

def count_trufflehog(path: str) -> int:
    data = load_json(path)
    return count_items(data, lambda i: isinstance(i, dict) and i.get("Verified"))


def count_semgrep(path: str) -> int:
    data = load_json(path) or {}
    results = data.get("results", [])
    return count_items(results, lambda r: r.get("extra", {}).get("severity", "").lower() in ("high", "error"))


def count_snyk_vulns(path: str) -> int:
    data = load_json(path) or {}
    return count_items(data.get("vulnerabilities", []), lambda v: v.get("severity") == "critical")


def count_checkov(path: str) -> int:
    data = load_json(path) or {}
    failed = data.get("results", {}).get("failed_checks", [])
    return count_items(failed, lambda f: f.get("severity") == "CRITICAL")


def count_trivy(path: str) -> int:
    data = load_json(path) or {}
    if not data:
        return 0
    results = data.get("Results", [{}])
    vulns = results[0].get("Vulnerabilities", [])
    return count_items(vulns, lambda v: v.get("Severity") in ("HIGH", "CRITICAL"))


def build_epss_details(epss_data: Dict[str, Any]) -> str:
    high = epss_data.get("high_risk", [])
    if not high:
        return "No EPSS/KEV high-risk vulnerabilities."
    lines = []
    for item in high:
        cve = item.get("cve")
        epss = item.get("epss")
        kev_flag = item.get("is_kev")
        lines.append(f"- `{cve}` (EPSS={epss}, KEV={kev_flag})")
    return "\n".join(lines)


# ============================================================
# Message Builders
# ============================================================

def build_main_blocks(repo: str, sha: str, run: str,
                      static_crit: int, epss_high: int,
                      epss_mode: str, epss_thr: str) -> List[Dict[str, Any]]:

    status = "FAILED" if (static_crit > 0 or epss_high > 0) else "PASSED"
    icon = "🚨" if status == "FAILED" else "✅"

    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{icon} SECURITY GATE {status}"}
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                slack_field("Static Critical", static_crit),
                slack_field("EPSS High-Risk", epss_high),
                slack_field("EPSS Mode", epss_mode),
                slack_field("Threshold", epss_thr),
            ],
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Repo:* `{repo}`\n*Commit:* `{sha}`\n*Run:* `{run}`"
            },
        },
    ]


def post_thread_reply(token: str, channel: str, thread_ts: str,
                      title: str, body: str) -> None:
    """Post a thread reply under the main message."""
    slack_post(
        token,
        {"channel": channel, "thread_ts": thread_ts, "text": f"*{title}*\n{body}"}
    )


# ============================================================
# Main Execution
# ============================================================

def main() -> None:
    token = os.getenv("SLACK_TOKEN")
    channel = os.getenv("SLACK_CHANNEL", "#devsecops")

    if not token:
        print("[ERROR] SLACK_TOKEN missing.")
        return

    repo = os.getenv("GITHUB_REPOSITORY", "repo")
    sha = os.getenv("GITHUB_SHA", "")[:7]
    run = os.getenv("GITHUB_RUN_NUMBER", "?")

    epss_path = os.getenv("EPSS_FINDINGS", "security-reports/epss-findings.json")
    static_crit = int(os.getenv("STATIC_CRITICAL", "0"))
    epss_mode = os.getenv("EPSS_MODE", "C")
    epss_thr = os.getenv("EPSS_THRESHOLD", "0.5")

    epss_data = load_json(epss_path) or {}
    epss_high = len(epss_data.get("high_risk", []))

    # ---------------------------------------------------------
    # MAIN MESSAGE
    # ---------------------------------------------------------
    main_msg = slack_post(
        token,
        {
            "channel": channel,
            "blocks": build_main_blocks(
                repo=repo,
                sha=sha,
                run=run,
                static_crit=static_crit,
                epss_high=epss_high,
                epss_mode=epss_mode,
                epss_thr=epss_thr,
            ),
        },
    )

    thread_ts = main_msg.get("ts")
    if not thread_ts:
        print("[ERROR] Missing Slack thread timestamp (ts).")
        return

    # ---------------------------------------------------------
    # THREAD REPLIES — scanner-by-scanner
    # ---------------------------------------------------------

    scanners = [
        ("TruffleHog Verified Secrets", "all-reports/reports-trufflehog/trufflehog.json", count_trufflehog),
        ("Semgrep Findings", "all-reports/reports-semgrep/semgrep.json", count_semgrep),
        ("Snyk Code", "all-reports/reports-snyk/snyk-code.json", count_snyk_vulns),
        ("Snyk SCA", "all-reports/reports-snyk/snyk-sca.json", count_snyk_vulns),
        ("Checkov Ansible", "all-reports/reports-checkov/checkov_ansible.json", count_checkov),
        ("Trivy Config Scan", "all-reports/reports-trivy/trivy.json", count_trivy),
    ]

    for title, path, func in scanners:
        count = func(path)
        post_thread_reply(
            token, channel, thread_ts,
            title,
            f"Findings: `{count}`\nFile: `{path}`"
        )

    # EPSS / KEV detail
    epss_details = build_epss_details(epss_data)
    post_thread_reply(token, channel, thread_ts, "EPSS/KEV Detail", epss_details)

    print("[OK] Slack main message + threaded replies delivered.")


if __name__ == "__main__":
    main()
