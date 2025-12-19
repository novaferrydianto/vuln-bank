#!/usr/bin/env python3
"""
Create GitHub Check Run for Composite Security Gate
Enterprise v3.6 – Vuln Bank
"""

import os
import json
import requests


def load_json(path: str) -> dict:
    if not os.path.exists(path):
        raise SystemExit(f"[ERROR] Missing JSON: {path}")
    with open(path) as f:
        return json.load(f)


def main():
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    sha = os.environ.get("GITHUB_SHA", "")
    composite_path = "security-reports/composite-gate.json"

    composite = load_json(composite_path)

    status = "completed"
    conclusion = "success" if composite["decision"] == "PASS" else "failure"

    title = f"Composite Security Gate: {composite['decision']}"
    summary = (
        f"EPSS high-risk: {composite['epss_high_risk']}\n"
        f"LLM risk: {composite['llm_risk_score']}\n"
        f"LLM exploit likelihood: {composite['llm_exploit_likelihood']}\n"
        f"Fail reasons: {composite['fail_reasons']}"
    )

    url = f"https://api.github.com/repos/{repo}/check-runs"

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
    }

    payload = {
        "name": "Composite Security Gate",
        "head_sha": sha,
        "status": status,
        "conclusion": conclusion,
        "output": {
            "title": title,
            "summary": summary,
        },
    }

    r = requests.post(url, headers=headers, json=payload)

    if r.status_code >= 300:
        raise SystemExit(f"[ERROR] GitHub Check Run failed: {r.status_code} {r.text}")

    print("[OK] Composite Check Run submitted.")


if __name__ == "__main__":
    main()
