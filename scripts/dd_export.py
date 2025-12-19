#!/usr/bin/env python3
"""
Export DefectDojo metrics for dashboards.

Output:
  docs/data/defectdojo-sla-weekly.json
  docs/data/defectdojo-summary.json
"""

import os
import json
import requests
from pathlib import Path

DD_URL = os.getenv("DEFECTDOJO_URL", "").rstrip("/")
DD_API_KEY = os.getenv("DEFECTDOJO_API_KEY", "")
DD_PRODUCT_ID = os.getenv("DEFECTDOJO_PRODUCT_ID", "")

API = f"{DD_URL}/api/v2"
headers = {"Authorization": f"Token {DD_API_KEY}"}

OUTPUT_SUMMARY = Path("docs/data/defectdojo-summary.json")
OUTPUT_SLA = Path("docs/data/defectdojo-sla-weekly.json")

def fetch_all(endpoint):
    items = []
    url = f"{API}/{endpoint}"
    while url:
        r = requests.get(url, headers=headers)
        if r.status_code != 200:
            break
        data = r.json()
        items.extend(data.get("results", []))
        url = data.get("next")
    return items

def summarize(findings):
    summary = {
        "total": len(findings),
        "severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
        "open": 0,
        "closed": 0,
    }
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        if sev not in summary["severity"]:
            summary["severity"][sev] = 0
        summary["severity"][sev] += 1
        if f.get("active"):
            summary["open"] += 1
        else:
            summary["closed"] += 1
    return summary

def main():
    findings = fetch_all(f"findings/?product={DD_PRODUCT_ID}")
    summary = summarize(findings)

    OUTPUT_SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_SLA.parent.mkdir(parents=True, exist_ok=True)

    OUTPUT_SUMMARY.write_text(json.dumps(summary, indent=2))
    OUTPUT_SLA.write_text(json.dumps(findings, indent=2))

    print(f"[DD] Exported summary → {OUTPUT_SUMMARY}")
    print(f"[DD] Exported SLA → {OUTPUT_SLA}")

if __name__ == "__main__":
    main()
