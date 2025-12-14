#!/usr/bin/env python3
import os, sys, json, requests

DD_URL = os.environ["DEFECTDOJO_URL"].rstrip("/")
API_KEY = os.environ["DEFECTDOJO_API_KEY"]
ENG_ID = os.environ.get("DEFECTDOJO_ENGAGEMENT_ID", "").strip()

if not ENG_ID:
    print("[SKIP] No DEFECTDOJO_ENGAGEMENT_ID provided")
    sys.exit(0)

HEADERS = {
    "Authorization": f"Token {API_KEY}",
    "Accept": "application/json",
    "Content-Type": "application/json",
}

def get_all(url, params=None):
    items = []
    while url:
        r = requests.get(url, headers=HEADERS, params=params, timeout=30)
        r.raise_for_status()
        data = r.json()
        items.extend(data.get("results", []))
        url = data.get("next")
        params = None
    return items

# 1) Fetch active findings in this engagement
findings_url = f"{DD_URL}/api/v2/findings/"
findings = get_all(findings_url, params={"engagement": ENG_ID, "active": "true", "limit": 200})

if not findings:
    print("[OK] No active findings to close for engagement", ENG_ID)
else:
    closed = 0
    for f in findings:
        fid = f["id"]
        # Idempotent patch: set inactive + mitigated if not already
        payload = {
            "active": False,
            "is_mitigated": True,
            "mitigation": f"Auto-closed on PR merge (engagement {ENG_ID}).",
        }
        try:
            r = requests.patch(f"{DD_URL}/api/v2/findings/{fid}/", headers=HEADERS, data=json.dumps(payload), timeout=30)
            r.raise_for_status()
            closed += 1
        except Exception as e:
            print(f"[WARN] Failed to close finding {fid}: {e}")

    print(f"[OK] Closed {closed}/{len(findings)} findings for engagement {ENG_ID}")

# 2) Mark engagement completed (optional but recommended)
try:
    payload = {"status": "Completed"}
    r = requests.patch(f"{DD_URL}/api/v2/engagements/{ENG_ID}/", headers=HEADERS, data=json.dumps(payload), timeout=30)
    r.raise_for_status()
    print("[OK] Engagement marked Completed:", ENG_ID)
except Exception as e:
    print("[WARN] Failed to close engagement:", e)
