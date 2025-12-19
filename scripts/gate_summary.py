#!/usr/bin/env python3
"""
gate_summary.py
Generate PR Security Summary Markdown + update PR comment.
"""

import os
import json
import urllib.request
import urllib.error


GITHUB_API = "https://api.github.com"
TAG_START = "<!-- security-summary-start -->"
TAG_END = "<!-- security-summary-end -->"


def gh(method, url, token, payload=None):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "gate-summary-bot"
    }
    data = None
    if payload:
        data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except Exception as e:
        print(f"[ERROR] API {method} {url}: {e}")
        return None


def get_pr_number():
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return None
    with open(event_path) as f:
        data = json.load(f)
    return data.get("pull_request", {}).get("number")


def read_json(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def build_summary(epss):
    if not epss:
        return f"{TAG_START}\n### 🛡 Security Summary\nNo data.\n{TAG_END}"

    hr = epss.get("high_risk", [])
    md = []
    md.append("### 🛡 Security Summary")
    md.append(f"- Total Unique CVEs: {epss.get('total_unique_cves', 0)}")
    md.append(f"- High-Risk: **{len(hr)}**\n")

    if hr:
        md.append("#### High-Risk CVEs:")
        for item in hr[:10]:
            md.append(f"- `{item['cve']}` (EPSS {item['epss']}, CVSS {item['cvss']})")
    else:
        md.append("No high-risk vulnerabilities.")

    return f"{TAG_START}\n" + "\n".join(md) + f"\n{TAG_END}"


def update_pr_comment(repo, token, pr, content):
    url = f"{GITHUB_API}/repos/{repo}/issues/{pr}/comments"
    comments = gh("GET", url, token)

    if comments:
        for c in comments:
            if TAG_START in c.get("body", ""):
                gh("PATCH", f"{url}/{c['id']}", token, {"body": content})
                print("[INFO] Updated existing PR summary.")
                return

    gh("POST", url, token, {"body": content})
    print("[INFO] Created new PR summary comment.")


def main():
    repo = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GITHUB_TOKEN")

    epss = read_json("security-reports/epss-findings.json")
    summary = build_summary(epss)

    pr = get_pr_number()
    if pr:
        update_pr_comment(repo, token, pr, summary)

    print(summary)


if __name__ == "__main__":
    main()
