#!/usr/bin/env python3
import os
import json
import urllib.request
import urllib.error


def safe_load_json(path: str):
    workspace = os.path.realpath(os.getenv("GITHUB_WORKSPACE", os.getcwd()))
    target = os.path.realpath(path)

    if not target.startswith(workspace + os.sep):
        print(f"[WARN] Unsafe EPSS path: {path}")
        return None

    if not os.path.exists(target):
        return None

    try:
        with open(target) as f:
            return json.load(f)
    except Exception:
        return None


def github_api(path, method="POST", body=None):
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("[INFO] No token; skip GH integration.")
        return None

    url = f"https://api.github.com{path}"

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "vuln-bank-epss",
    }

    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            txt = resp.read().decode()
            return json.loads(txt) if txt else None
    except Exception as e:
        print(f"[WARN] GitHub API error: {e}")
        return None


def get_pr():
    event = os.getenv("GITHUB_EVENT_PATH")
    if not event:
        return None
    try:
        with open(event) as f:
            data = json.load(f)
        return data.get("number")
    except Exception:
        return None


def build_msg(data):
    high = data.get("high_risk", [])
    threshold = data.get("threshold")
    mode = data.get("mode")

    if not high:
        return (
            f"EPSS Gate PASSED\n"
            f"- Mode: `{mode}`\n"
            f"- Threshold: `{threshold}`\n"
            f"- High-risk: 0\n"
        )

    body = [
        f"EPSS Gate Results:",
        f"- Mode: `{mode}`",
        f"- Threshold: `{threshold}`",
        f"- High-risk findings: `{len(high)}`",
        "",
        "| CVE | Severity | EPSS | KEV | Package | Version | Reasons |",
        "| --- | -------- | ---- | --- | ------- | ------- | ------- |",
    ]

    for item in high[:20]:
        kev = "YES" if item.get("is_kev") else "NO"
        body.append(
            f"| {item.get('cve')} | {item.get('severity')} | "
            f"{item.get('epss'):.2f} | {kev} | {item.get('pkg')} | "
            f"{item.get('version')} | {', '.join(item.get('reasons', []))} |"
        )

    return "\n".join(body)


def main():
    epss_path = os.getenv("EPSS_FINDINGS")
    data = safe_load_json(epss_path)

    if not data:
        print("[INFO] No EPSS data; skipping PR comment.")
        return

    repo = os.getenv("GITHUB_REPOSITORY")
    pr = get_pr()
    if not pr:
        print("[INFO] Not PR event.")
        return

    msg = build_msg(data)
    path = f"/repos/{repo}/issues/{pr}/comments"
    github_api(path, "POST", {"body": msg})

    print(f"[EPSS] Posted PR comment #{pr}")


if __name__ == "__main__":
    main()
