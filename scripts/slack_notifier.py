#!/usr/bin/env python3
"""
Slack Notifier (Enterprise Grade v2025 - Refactored)

Features:
- Sends a main "Security Gate" summary message with rich Slack blocks.
- Sends per-scanner findings as threaded replies (TruffleHog, Semgrep, Snyk, Checkov, Trivy).
- Sends EPSS/KEV detailed findings as another threaded reply.
- Structured and modular to keep Cognitive Complexity low and pass SonarQube checks.
"""

import json
import os
import requests


SLACK_POST = "https://slack.com/api/chat.postMessage"


# ======================================================
# Generic helpers
# ======================================================
def load_json(path: str):
    """Load JSON file if exists, otherwise return None."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def slack_api(token: str, payload: dict) -> dict:
    """Call Slack chat.postMessage API and return the parsed JSON response."""
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": f"Bearer {token}",
    }
    try:
        response = requests.post(
            SLACK_POST,
            headers=headers,
            json=payload,
            timeout=12,
        )
        data = response.json()
    except Exception as exc:
        print(f"[ERROR] Slack request failed: {exc}")
        return {}

    if not data.get("ok"):
        print(f"[WARN] Slack API error: {data}")
    return data


def build_metric(title: str, value, emoji: str = "•") -> dict:
    """Build a Slack mrkdwn field for metric-style display."""
    return {"type": "mrkdwn", "text": f"*{emoji} {title}:*\n{value}"}


def send_reply(token: str, channel: str, thread_ts: str, title: str, body: str) -> dict:
    """Send a threaded reply message under the main Slack message."""
    payload = {
        "channel": channel,
        "thread_ts": thread_ts,
        "text": f"*{title}*\n{body}",
    }
    return slack_api(token, payload)


# ======================================================
# Per-scanner counters (kept small & focused)
# ======================================================
def count_trufflehog(path: str) -> int:
    data = load_json(path) or []
    return sum(1 for item in data if isinstance(item, dict) and item.get("Verified"))


def count_semgrep(path: str) -> int:
    data = load_json(path) or {}
    results = data.get("results", [])
    severities = {"error", "high"}
    return sum(
        1
        for finding in results
        if finding.get("extra", {}).get("severity", "").lower() in severities
    )


def count_snyk_code(path: str) -> int:
    data = load_json(path) or {}
    vulns = data.get("vulnerabilities", [])
    return sum(1 for v in vulns if v.get("severity") == "critical")


def count_snyk_sca(path: str) -> int:
    data = load_json(path) or {}
    vulns = data.get("vulnerabilities", [])
    return sum(1 for v in vulns if v.get("severity") == "critical")


def count_checkov(path: str) -> int:
    data = load_json(path) or {}
    failed = data.get("results", {}).get("failed_checks", [])
    return sum(1 for f in failed if f.get("severity") == "CRITICAL")


def count_trivy(path: str) -> int:
    data = load_json(path) or {}
    if not data:
        return 0

    results = data.get("Results", [])
    if not results:
        return 0

    vulns = results[0].get("Vulnerabilities", [])
    return sum(
        1 for v in vulns if v.get("Severity", "") in ("HIGH", "CRITICAL")
    )


SCANNERS = [
    ("TruffleHog (Verified Secrets)", "all-reports/reports-trufflehog/trufflehog.json", count_trufflehog),
    ("Semgrep Findings", "all-reports/reports-semgrep/semgrep.json", count_semgrep),
    ("Snyk Code", "all-reports/reports-snyk/snyk-code.json", count_snyk_code),
    ("Snyk SCA", "all-reports/reports-snyk/snyk-sca.json", count_snyk_sca),
    ("Checkov (Ansible)", "all-reports/reports-checkov/checkov_ansible.json", count_checkov),
    ("Trivy Config Scan", "all-reports/reports-trivy/trivy.json", count_trivy),
]


# ======================================================
# MAIN
# ======================================================
def main() -> None:
    # Core envs
    slack_token = os.getenv("SLACK_TOKEN")
    channel = os.getenv("SLACK_CHANNEL", "#devsecops")

    static_crit = int(os.getenv("STATIC_CRITICAL", "0"))
    epss_path = os.getenv("EPSS_FINDINGS", "security-reports/epss-findings.json")
    epss_mode = os.getenv("EPSS_MODE", "C")
    epss_thr = os.getenv("EPSS_THRESHOLD", "0.5")

    repo = os.getenv("GITHUB_REPOSITORY", "repo")
    sha = os.getenv("GITHUB_SHA", "")[:7]
    run_number = os.getenv("GITHUB_RUN_NUMBER", "?")

    if not slack_token:
        print("[ERROR] SLACK_TOKEN missing.")
        return

    # EPSS / KEV
    epss_data = load_json(epss_path) or {}
    epss_high_risk = epss_data.get("high_risk", [])
    epss_high = len(epss_high_risk)

    gate_failed = static_crit > 0 or epss_high > 0
    status = "FAILED" if gate_failed else "PASSED"
    icon = "🚨" if gate_failed else "✅"

    # Build main summary blocks
    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{icon} SECURITY GATE {status}",
            },
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                build_metric("Static Critical", static_crit, "🔥"),
                build_metric("EPSS/KEV High-Risk", epss_high, "🛑"),
                build_metric("EPSS Mode", epss_mode, "⚙️"),
                build_metric("Threshold", epss_thr, "📉"),
            ],
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Repo:* `{repo}`\n*Commit:* `{sha}`\n*Run:* `{run_number}`",
            },
        },
    ]

    main_msg = slack_api(
        slack_token,
        {
            "channel": channel,
            "blocks": blocks,
        },
    )

    thread_ts = main_msg.get("ts")
    if not thread_ts:
        print("[ERROR] Cannot create thread replies (ts is null).")
        return

    # Per-scanner threaded replies
    for scanner_name, report_path, counter in SCANNERS:
        count = counter(report_path)
        body = f"Findings: `{count}`\nFile: `{report_path}`"
        send_reply(slack_token, channel, thread_ts, scanner_name, body)

    # EPSS / KEV detailed reply
    if epss_high_risk:
        details_lines = [
            f"- `{item.get('cve')}` (EPSS={item.get('epss')}, KEV={item.get('is_kev')})"
            for item in epss_high_risk
        ]
        details = "\n".join(details_lines)
    else:
        details = "No EPSS/KEV high-risk items."

    send_reply(slack_token, channel, thread_ts, "EPSS/KEV Detailed", details)

    print("[OK] Slack notification and thread replies delivered.")


if __name__ == "__main__":
    main()
