#!/usr/bin/env python3
"""
Universal importer to DefectDojo.

Environment Variables:
  DEFECTDOJO_URL
  DEFECTDOJO_API_KEY
  DEFECTDOJO_PRODUCT_ID
  DEFECTDOJO_ENGAGEMENT_NAME
"""

import os
import json
import requests
from pathlib import Path

DD_URL = os.getenv("DEFECTDOJO_URL", "").rstrip("/")
DD_API_KEY = os.getenv("DEFECTDOJO_API_KEY", "")
DD_PRODUCT_ID = os.getenv("DEFECTDOJO_PRODUCT_ID", "")
ENGAGEMENT_NAME = os.getenv("DEFECTDOJO_ENGAGEMENT_NAME", "")

API = f"{DD_URL}/api/v2"
headers = {"Authorization": f"Token {DD_API_KEY}"}

DD_SCAN_MAPPING = {
    "trivy.json": "Trivy Scan",
    "snyk-sca.json": "Snyk Scan",
    "snyk-iac.json": "Snyk IaC",
    "snyk-code.json": "Snyk Code Scan",
    "semgrep.json": "Semgrep JSON Report",
    "checkov_ansible.json": "Checkov Scan",
    "checkov_docker.json": "Checkov Scan",
    "codeql-results.sarif": "SARIF",
    "zap_report.json": "ZAP Scan",
}

def get_engagement_id():
    r = requests.get(f"{API}/engagements/?name={ENGAGEMENT_NAME}", headers=headers)
    if r.status_code != 200:
        print(f"[DD] Failed to search engagement: {r.text}")
        return None

    res = r.json()
    if res.get("count", 0) == 0:
        print(f"[DD] No engagement found: {ENGAGEMENT_NAME}")
        return None

    return res["results"][0]["id"]

def import_file(path: Path, engagement_id: int):
    filename = path.name
    scan_type = DD_SCAN_MAPPING.get(filename)

    if not scan_type:
        print(f"[DD] No scan mapping for file: {filename}")
        return

    print(f"[DD] Importing {filename} as {scan_type}")

    files = {
        "file": (filename, path.read_bytes()),
    }
    data = {
        "engagement": engagement_id,
        "scan_type": scan_type,
        "product": DD_PRODUCT_ID,
        "active": True,
        "verified": True,
        "close_old_findings": True,
        "minimum_severity": "Low",
    }

    r = requests.post(
        f"{API}/import-scan/?close_old_findings=true",
        headers=headers,
        files=files,
        data=data,
    )

    if r.status_code not in (200, 201):
        print(f"[DD] Import failed for {filename}: {r.text}")
    else:
        print(f"[DD] Imported: {filename}")

def main():
    engagement_id = get_engagement_id()
    if not engagement_id:
        print("[DD] Cannot continue without engagement ID")
        return

    report_dir = Path("security-reports")
    if not report_dir.exists():
        print("[DD] No report directory found")
        return

    for path in report_dir.glob("*.json"):
        import_file(path, engagement_id)

    # include SARIF
    sarif = Path("security-reports/codeql-results.sarif")
    if sarif.exists():
        import_file(sarif, engagement_id)

    print("[DD] Import completed")

if __name__ == "__main__":
    main()
