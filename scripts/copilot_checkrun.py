#!/usr/bin/env python3

import os, json
import requests

GH_TOKEN = os.environ["GITHUB_TOKEN"]
REPO = os.environ["GITHUB_REPOSITORY"]
SHA = os.environ["GITHUB_SHA"]

def create_checkrun(name, summary, conclusion="neutral"):
    url = f"https://api.github.com/repos/{REPO}/check-runs"
    headers = {
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github+json",
    }
    body = {
        "name": name,
        "head_sha": SHA,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": name,
            "summary": summary,
        }
    }
    r = requests.post(url, headers=headers, json=body)
    r.raise_for_status()

def main():
    path = "security-reports/copilot-security.json"
    if not os.path.exists(path):
        create_checkrun("Copilot Security", "No data found", "neutral")
        return

    data = json.load(open(path))
    risk = data.get("risk_level", 0)

    conclusion = "failure" if risk >= 0.7 else "success"
    summary = f"Copilot detected risk level: {risk}"

    create_checkrun("Copilot Security Review", summary, conclusion)

if __name__ == "__main__":
    main()
