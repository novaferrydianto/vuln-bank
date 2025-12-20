#!/usr/bin/env python3
import requests
import os
import sys
from datetime import datetime, timedelta

DD_URL = os.getenv("DEFECTDOJO_URL")
DD_API_KEY = os.getenv("DEFECTDOJO_API_KEY")
PRODUCT_ID = os.getenv("DEFECTDOJO_PRODUCT_ID")
EPSS_THRESHOLD = float(os.getenv("EPSS_THRESHOLD", "0.5"))

HEADERS = {"Authorization": f"Token {DD_API_KEY}", "Content-Type": "application/json"}

def paginated_get(url):
    items = []
    while url:
        r = requests.get(url, headers=HEADERS)
        if r.status_code != 200: break
        data = r.json()
        items.extend(data.get("results", []))
        url = data.get("next")
    return items

def map_assignee(file_path):
    if not file_path: return "team-general"
    mappings = {"auth": "team-backend", "database": "team-db", "static": "team-frontend", "Dockerfile": "team-devops"}
    for key, team in mappings.items():
        if key in file_path: return team
    return "team-core"

def enhance_and_cleanup():
    print("[INFO] Starting DefectDojo Advanced Maintenance...")
    
    findings = paginated_get(f"{DD_URL}/api/v2/findings/?product={PRODUCT_ID}&active=true")
    cutoff = datetime.utcnow() - timedelta(days=7)

    for f in findings:
        fid = f["id"]
        current_tags = f.get("tags", [])
        file_path = f.get("file_path", "")
        date_found = datetime.strptime(f["date"], "%Y-%m-%d")
        
        # 1. Re-tagging based on path (Auto-assign)
        team_tag = map_assignee(file_path)
        if team_tag not in current_tags:
            current_tags.append(team_tag)

        # 2. Logic: Close Old Low-Risk Findings
        if date_found < cutoff and f["severity"] not in ("Critical", "High"):
            print(f"[CLOSE] Stale finding #{fid}")
            requests.patch(f"{DD_URL}/api/v2/findings/{fid}/", headers=HEADERS, 
                           json={"active": False, "is_mitigated": True})
            continue

        # 3. Update Finding Tags
        requests.patch(f"{DD_URL}/api/v2/findings/{fid}/", headers=HEADERS, 
                       json={"tags": current_tags})

    print("[INFO] Maintenance complete.")

if __name__ == "__main__":
    enhance_and_cleanup()