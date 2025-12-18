#!/usr/bin/env python3
"""
Slack Notifier (Enterprise Grade v2025)
- Rich Blocks for the main gate status
- Thread replies per scanner (TruffleHog / Semgrep / Snyk / Trivy / Checkov / EPSS)
- All replies are child messages of the main Slack parent message
"""

import json
import os
import requests
from datetime import datetime


SLACK_POST = "https://slack.com/api/chat.postMessage"


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def slack_api(token, payload):
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": f"Bearer {token}",
    }
    r = requests.post(SLACK_POST, headers=headers, json=payload, timeout=12)
    try:
        data = r.json()
        if not data.get("ok"):
            print(f"[WARN] Slack API error: {data}")
        return data
    except Exception:
        print("[WARN] Failed to parse Slack API response")
        return {}


def build_metric(title, value, emoji="•"):
    return {"type": "mrkdwn", "text": f"*{emoji} {title}:*\n{value}"}


def summary_scanner(name, file_path, jq_desc, count):
    return f"*{name}*: `{count}` findings\nFile: `{file_path}`\n{jq_desc}"


def main():
    slack_token = os.getenv("SLACK_TOKEN")
    channel = os.getenv("SLACK_CHANNEL", "#devsecops")
    webhook_fallback = os.getenv("SLACK_WEBHOOK_URL")  # fallback for main block only

    static_crit = int(os.getenv("STATIC_CRITICAL", "0"))
    epss_path = os.getenv("EPSS_FINDINGS", "security-reports/epss-findings.json")
    epss_mode = os.getenv("EPSS_MODE", "C")
    epss_thr = os.getenv("EPSS_THRESHOLD", "0.5")
    repo = os.getenv("GITHUB_REPOSITORY", "repo")
    sha = os.getenv("GITHUB_SHA", "")[:7]
    run = os.getenv("GITHUB_RUN_NUMBER", "?")

    if not slack_token:
        print("[ERROR] SLACK_TOKEN missing.")
        return

    # -------------------------
    # EPSS
    # -------------------------
    epss_data = load_json(epss_path) or {}
    epss_high = len(epss_data.get("high_risk", []))

    status = "FAILED" if static_crit > 0 or epss_high > 0 else "PASSED"
    icon = "🚨" if status == "FAILED" else "✅"
    color = "#ff0000" if status == "FAILED" else "#2eb886"

    # -------------------------
    # Main Slack HEAD message
    # -------------------------
    main_blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"{icon} SECURITY GATE {status}"}
        },
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                build_metric("Static Critical", static_crit, "🔥"),
                build_metric("EPSS/KEV High-Risk", epss_high, "🛑"),
                build_metric("EPSS Mode", epss_mode, "⚙️"),
                build_metric("Threshold", epss_thr, "📉")
            ]
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Repo:* `{repo}`\n*Commit:* `{sha}`\n*Run:* `{run}`"
            }
        }
    ]

    # Send main message using chat.postMessage
    main_msg = slack_api(
        slack_token,
        {
            "channel": channel,
            "blocks": main_blocks
        }
    )

    thread_ts = main_msg.get("ts")
    if not thread_ts:
        print("[ERROR] Cannot create thread replies (ts null).")
        return

    # -------------------------
    # Helper: reply builder
    # -------------------------
    def reply(title, body):
        return slack_api(
            slack_token,
            {
                "channel": channel,
                "thread_ts": thread_ts,
                "text": f"*{title}*\n{body}"
            }
        )

    # -------------------------
    # Thread Reply: TruffleHog
    # -------------------------
    tr_path = "all-reports/reports-trufflehog/trufflehog.json"
    tr_data = load_json(tr_path) or []
    tr_count = sum(1 for i in tr_data if isinstance(i, dict) and i.get("Verified"))
    reply("TruffleHog (Verified Secrets)", f"Verified Secrets: `{tr_count}`\nFile: `{tr_path}`")

    # -------------------------
    # Semgrep
    # -------------------------
    sg_path = "all-reports/reports-semgrep/semgrep.json"
    sg_data = load_json(sg_path) or {}
    sg_results = sg_data.get("results", [])
    sg_crit = sum(1 for r in sg_results if r.get("extra", {}).get("severity", "").lower() in ["error", "high"])
    reply("Semgrep Findings", f"ERROR+HIGH findings: `{sg_crit}`\nFile: `{sg_path}`")

    # -------------------------
    # Snyk Code
    # -------------------------
    sc_path = "all-reports/reports-snyk/snyk-code.json"
    snyk_code = load_json(sc_path) or {}
    sc_crit = len([v for v in snyk_code.get("vulnerabilities", []) if v.get("severity") == "critical"])
    reply("Snyk Code", f"Critical vulns: `{sc_crit}`\nFile: `{sc_path}`")

    # -------------------------
    # Snyk SCA
    # -------------------------
    ss_path = "all-reports/reports-snyk/snyk-sca.json"
    snyk_sca = load_json(ss_path) or {}
    ss_crit = len([v for v in snyk_sca.get("vulnerabilities", []) if v.get("severity") == "critical"])
    reply("Snyk SCA", f"Critical vulns: `{ss_crit}`\nFile: `{ss_path}`")

    # -------------------------
    # Checkov
    # -------------------------
    ck_path = "all-reports/reports-checkov/checkov_ansible.json"
    ck_data = load_json(ck_path) or {}
    ck_failed = ck_data.get("results", {}).get("failed_checks", [])
    ck_crit = len([f for f in ck_failed if f.get("severity") == "CRITICAL"])
    reply("Checkov (Ansible)", f"CRITICAL failed checks: `{ck_crit}`\nFile: `{ck_path}`")

    # -------------------------
    # Trivy
    # -------------------------
    tv_path = "all-reports/reports-trivy/trivy.json"
    tv_data = load_json(tv_path) or {}
    tv_crit = len([
        v for v in tv_data.get("Results", [{}])[0].get("Vulnerabilities", [])
        if v.get("Severity", "") in ["HIGH", "CRITICAL"]
    ]) if tv_data else 0
    reply("Trivy Config Scan", f"HIGH+CRITICAL: `{tv_crit}`\nFile: `{tv_path}`")

    # -------------------------
    # EPSS/KEV — detailed listing
    # -------------------------
    epss_list = epss_data.get("high_risk", [])
    if epss_list:
        details = "\n".join([f"- `{i.get('cve')}` (EPSS={i.get('epss')}, KV={i.get('is_kev')})" for i in epss_list])
    else:
        details = "No EPSS/KEV high-risk items."
    reply("EPSS/KEV Detailed", details)

    print("[OK] Slack notification + thread replies delivered.")


if __name__ == "__main__":
    main()
