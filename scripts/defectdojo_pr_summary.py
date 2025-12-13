#!/usr/bin/env python3
import os
import sys
import requests

DD_URL = os.environ.get("DEFECTDOJO_URL")
DD_TOKEN = os.environ.get("DEFECTDOJO_API_KEY")
ENGAGEMENT_ID = os.environ.get("DEFECTDOJO_ENGAGEMENT_ID")
REPO = os.environ.get("GITHUB_REPOSITORY")
PR = os.environ.get("PR_NUMBER")
GH_TOKEN = os.environ.get("GITHUB_TOKEN")

# ---------- SAFETY GUARDS ----------
if not ENGAGEMENT_ID:
    print("[SKIP] No DefectDojo engagement ID")
    sys.exit(0)

if not DD_URL or not DD_TOKEN:
    print("[SKIP] DefectDojo credentials missing")
    sys.exit(0)

headers = {
    "Authorization": f"Token {DD_TOKEN}",
    "Accept": "application/json",
}

# ---------- FETCH FINDINGS ----------
try:
    r = requests.get(
        f"{DD_URL}/api/v2/findings/",
        headers=headers,
        params={"engagement": ENGAGEMENT_ID, "limit": 500},
        timeout=10,   # ⬅️ IMPORTANT
    )
    r.raise_for_status()
except Exception as e:
    print(f"[SKIP] Cannot reach DefectDojo: {e}")
    sys.exit(0)

findings = r.json().get("results", [])

summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
for f in findings:
    sev = f.get("severity")
    if sev in summary:
        summary[sev] += 1

comment = f"""### 🔐 Security Scan Summary (DefectDojo)

| Severity | Count |
|---------|-------|
| Critical | {summary['Critical']} |
| High | {summary['High']} |
| Medium | {summary['Medium']} |
| Low | {summary['Low']} |

DefectDojo Engagement ID: `{ENGAGEMENT_ID}`
"""

# ---------- POST COMMENT ----------
try:
    requests.post(
        f"https://api.github.com/repos/{REPO}/issues/{PR}/comments",
        headers={"Authorization": f"Bearer {GH_TOKEN}"},
        json={"body": comment},
        timeout=10,
    )
    print("[OK] PR comment posted")
except Exception as e:
    print(f"[WARN] Failed posting PR comment: {e}")
