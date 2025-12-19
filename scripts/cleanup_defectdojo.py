#!/usr/bin/env python3
import requests
import os
import sys
import time
import re
from datetime import datetime, timedelta

DD_URL = os.getenv("DEFECTDOJO_URL")
DD_API_KEY = os.getenv("DEFECTDOJO_API_KEY")
PRODUCT_ID = os.getenv("DEFECTDOJO_PRODUCT_ID")

if not DD_URL or not DD_API_KEY or not PRODUCT_ID:
    print("[ERROR] Missing required environment variables!")
    sys.exit(1)

HEADERS = {
    "Authorization": f"Token {DD_API_KEY}",
    "Content-Type": "application/json",
}

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss?cve="

# ======================================================
# HELPER API
# ======================================================
def paginated_get(url):
    items = []
    while url:
        r = requests.get(url, headers=HEADERS)
        if r.status_code != 200:
            print(f"[ERROR] GET failed: {r.text}")
            return items
        data = r.json()
        items.extend(data.get("results", []))
        url = data.get("next")
    return items


# ======================================================
# LOAD CISA KEV DATABASE
# ======================================================
def load_kev_db():
    try:
        r = requests.get(CISA_KEV_URL)
        data = r.json()
        return {x["cveID"]: True for x in data.get("vulnerabilities", [])}
    except:
        return {}


# ======================================================
# EPSS SCORING
# ======================================================
def fetch_epss(cve):
    try:
        r = requests.get(EPSS_API + cve)
        data = r.json().get("data", [])
        if not data:
            return None, None
        return float(data[0]["epss"]), float(data[0]["percentile"])
    except:
        return None, None


# ======================================================
# AUTO ASSIGN TEAM
# ======================================================
def map_assignee(file_path):
    if "auth" in file_path:
        return "team-backend"
    if "database" in file_path:
        return "team-db"
    if "static" in file_path:
        return "team-frontend"
    if "Dockerfile" in file_path:
        return "team-devops"
    return "team-backend-core"


# ======================================================
# REOPEN LOGIC (Finding muncul lagi)
# ======================================================
def reopen_finding(fid, title):
    url = f"{DD_URL}/api/v2/findings/{fid}/"
    payload = {
        "active": True,
        "is_Mitigated": False,
        "verified": True,
    }
    r = requests.patch(url, headers=HEADERS, json=payload)
    print(f"[REOPEN] Finding #{fid} – {title}")


# ======================================================
# ADD COMMENT
# ======================================================
def add_comment(fid, text):
    url = f"{DD_URL}/api/v2/notes/"
    payload = {"finding": fid, "entry": text, "private": False}
    requests.post(url, headers=HEADERS, json=payload)


# ======================================================
# AUTO CLOSE OLD FINDINGS
# ======================================================
def close_old_findings(days_limit=7):
    print("[INFO] Processing old findings...")
    open_findings = paginated_get(
        f"{DD_URL}/api/v2/findings/?product={PRODUCT_ID}&active=true&limit=500"
    )

    cutoff = datetime.utcnow() - timedelta(days=days_limit)

    for f in open_findings:
        fid = f["id"]
        sev = f["severity"].upper()
        date = datetime.strptime(f["date"], "%Y-%m-%d")
        title = f["title"]

        if sev not in ("HIGH", "CRITICAL"):
            continue
        if date > cutoff:
            continue

        # Close finding
        url = f"{DD_URL}/api/v2/findings/{fid}/"
        payload = {
            "active": False,
            "is_Mitigated": True,
            "verified": True,
            "mitigated": datetime.utcnow().strftime("%Y-%m-%d"),
        }
        r = requests.patch(url, headers=HEADERS, json=payload)
        if r.status_code in (200, 201):
            print(f"[CLOSED] #{fid} – {title}")
            add_comment(fid, "Auto-closed by CI (older than 7 days).")


# ======================================================
# AUTO TAG CISA KEV + ASSIGN TEAM + EPSS ENRICHMENT
# ======================================================
def enhance_findings():
    print("[INFO] Enhancing findings with KEV / EPSS / Assignment...")

    findings = paginated_get(
        f"{DD_URL}/api/v2/findings/?product={PRODUCT_ID}&limit=500"
    )
    kev_db = load_kev_db()

    for f in findings:
        fid = f["id"]
        title = f["title"]
        cve = f.get("cve")

        # Auto assign
        file_path = f.get("file_path", "unknown")
        
        team = map_assignee(file_path)

        # Auto-tag KEV
        kev_flag = cve in kev_db if cve else False

        # EPSS
        epss_score, epss_pct = (None, None)
        if cve:
            epss_score, epss_pct = fetch_epss(cve)

        payload = {
            "tags": team,
            "numerical_severity": f["numerical_severity"],
        }

        if kev_flag:
            payload["tags"] = "CISA-KEV"

        if epss_score:
            payload["epss_score"] = epss_score
            payload["epss_percentile"] = epss_pct

        url = f"{DD_URL}/api/v2/findings/{fid}/"
        requests.patch(url, headers=HEADERS, json=payload)

        if kev_flag:
            print(f"[KEV] #{fid} {cve} tagged as CISA KEV")

        if epss_score and epss_score >= 0.5:
            print(f"[EPSS HIGH] #{fid} {cve} – EPSS: {epss_score}")


# ======================================================
# MAIN
# ======================================================
if __name__ == "__main__":
    print("========== DEFECTDOJO ADVANCED CLEANUP ==========")
    enhance_findings()
    close_old_findings()
    print("========== COMPLETE ==========")
