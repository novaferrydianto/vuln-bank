#!/usr/bin/env python3
import os
import requests

DD_URL = os.environ["DEFECTDOJO_URL"].rstrip("/")
DD_KEY = os.environ["DEFECTDOJO_API_KEY"]
PR_NUMBER = os.environ.get("GITHUB_PR_NUMBER")

HEADERS = {
    "Authorization": f"Token {DD_KEY}",
    "Content-Type": "application/json",
}

def main():
    if not PR_NUMBER:
        print("[INFO] No PR number detected, skipping auto-close")
        return

    findings = requests.get(
        f"{DD_URL}/api/v2/findings/",
        headers=HEADERS,
        params={
            "active": "true",
            "tags": f"github_pr:{PR_NUMBER}",
            "limit": 500,
        },
    ).json()["results"]

    print(f"[INFO] Found {len(findings)} findings to auto-close")

    for f in findings:
        fid = f["id"]
        requests.patch(
            f"{DD_URL}/api/v2/findings/{fid}/",
            headers=HEADERS,
            json={
                "active": False,
                "verified": False,
                "false_p": False,
                "mitigated": True,
                "mitigation": "Fixed on merge to main branch",
            },
        )

if __name__ == "__main__":
    main()
