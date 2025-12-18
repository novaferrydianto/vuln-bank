#!/usr/bin/env python3
import os
import json
import urllib.request
import urllib.error


def safe_load_json(path: str):
    """
    Secure loader preventing path traversal by restricting file access
    to the GitHub workspace directory.
    """
    workspace = os.path.realpath(os.getenv("GITHUB_WORKSPACE", os.getcwd()))
    target = os.path.realpath(path)

    # Block traversal outside workspace
    if not target.startswith(workspace + os.sep):
        return None

    if not os.path.exists(target):
        return None

    try:
        with open(target) as f:
            return json.load(f)
    except Exception:
        return None


def send_slack(url: str, text: str):
    """
    Safe Slack webhook sender with URL validation (prevents SSRF).
    """
    if not url.startswith("https://") or "slack.com" not in url:
        print("[WARN] Invalid Slack webhook; skipping.")
        return

    payload = json.dumps({"text": text}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as exc:
        print(f"[WARN] Slack error: {exc}")


def summary_msg(data):
    """
    Builds human-readable EPSS summary for Slack.
    """
    status = "FAILED ❌" if data.get("gate_failed") else "PASSED ✅"
    mode = data.get("mode", "N/A")
    thr = data.get("threshold")
    total = data.get("total_vulns")
    high = data.get("high_risk_count")

    msg = [
        f"EPSS Gate {status}",
        f"- Mode: `{mode}`",
        f"- Threshold: `{thr}`",
        f"- Total vulnerabilities: `{total}`",
        f"- High-risk findings: `{high}`",
    ]
    return "\n".join(msg)


def main():
    epss_file = os.getenv("EPSS_FINDINGS")
    data = safe_load_json(epss_file)

    if not data:
        print("[INFO] No EPSS results found.")
        return

    slack = os.getenv("SLACK_URL")
    if not slack:
        print("[INFO] No Slack webhook provided.")
        return

    send_slack(slack, summary_msg(data))
    print("[EPSS] Slack summary sent.")


if __name__ == "__main__":
    main()
