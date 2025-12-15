#!/usr/bin/env python3
"""
DefectDojo auto-close findings on PR merge

- Safe to run multiple times
- Never blocks CI
- Retries + timeout
- Gracefully skips if DD is unreachable
"""

import os
import sys
import requests
from requests.adapters import HTTPAdapter, Retry

DD_URL = os.environ.get("DEFECTDOJO_URL", "").rstrip("/")
DD_KEY = os.environ.get("DEFECTDOJO_API_KEY")
PR_NUMBER = os.environ.get("GITHUB_PR_NUMBER")

if not DD_URL or not DD_KEY:
    print("[INFO] DefectDojo credentials not set, skipping auto-close")
    sys.exit(0)

HEADERS = {
    "Authorization": f"Token {DD_KEY}",
    "Content-Type": "application/json",
}


def session_with_retries() -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "PATCH"],
    )
    s.mount("http://", HTTPAdapter(max_retries=retries))
    s.mount("https://", HTTPAdapter(max_retries=retries))
    return s


def main():
    if not PR_NUMBER:
        print("[INFO] No PR number detected, skipping auto-close")
        return

    session = session_with_retries()

    try:
        resp = session.get(
            f"{DD_URL}/api/v2/findings/",
            headers=HEADERS,
            params={
                "active": "true",
                "tags": f"github_pr:{PR_NUMBER}",
                "limit": 500,
            },
            timeout=10,
        )
        resp.raise_for_status()
    except Exception as e:
        print(f"[WARN] Cannot reach DefectDojo, skipping auto-close: {e}")
        return

    findings = resp.json().get("results", [])
    print(f"[INFO] Found {len(findings)} findings to auto-close")

    for f in findings:
        fid = f["id"]
        try:
            session.patch(
                f"{DD_URL}/api/v2/findings/{fid}/",
                headers=HEADERS,
                json={
                    "active": False,
                    "verified": False,
                    "false_p": False,
                    "mitigated": True,
                    "mitigation": "Fixed on merge to main branch",
                },
                timeout=10,
            )
        except Exception as e:
            print(f"[WARN] Failed to close finding {fid}: {e}")

    print("[INFO] DefectDojo auto-close completed")


if __name__ == "__main__":
    main()
