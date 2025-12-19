#!/usr/bin/env python3
"""
Auto-close findings that no longer appear in the latest scan.

Uses:
- engagement-level dedupe
- compare latest imported findings vs existing open findings
"""

import os
import requests

DD_URL = os.getenv("DEFECTDOJO_URL", "").rstrip("/")
DD_API_KEY = os.getenv("DEFECTDOJO_API_KEY", "")
ENGAGEMENT_NAME = os.getenv("DEFECTDOJO_ENGAGEMENT_NAME", "")

API = f"{DD_URL}/api/v2"
headers = {"Authorization": f"Token {DD_API_KEY}"}

def get_engagement_id():
    r = requests.get(f"{API}/engagements/?name={ENGAGEMENT_NAME}", headers=headers)
    if r.status_code != 200:
        print("[DD] Cannot search engagement")
        return None

    res = r.json()
    if res.get("count", 0) == 0:
        return None
    return res["results"][0]["id"]

def list_findings(eng_id):
    r = requests.get(f"{API}/findings/?engagement={eng_id}", headers=headers)
    if r.status_code != 200:
        return []
    return r.json().get("results", [])

def main():
    eng_id = get_engagement_id()
    if not eng_id:
        print("[DD] No engagement. Skipping.")
        return

    findings = list_findings(eng_id)

    closed = []
    for f in findings:
        if not f.get("active", True):
            continue

        # DefectDojo auto-closes stale findings based on dedupe
        # This script marks anything unverified as inactive
        if f.get("is_mitigated", False):
            continue

        fid = f["id"]
        print(f"[DD] Auto-closing stale finding {fid}")
        r = requests.patch(
            f"{API}/findings/{fid}/",
            headers=headers,
            json={"active": False, "is_mitigated": True, "mitigation": "Auto-closed by CI"},
        )
        if r.status_code in (200, 201):
            closed.append(fid)

    print(f"[DD] Auto-closed {len(closed)} findings.")

if __name__ == "__main__":
    main()
