#!/usr/bin/env python3
import json
import hashlib
import argparse
import os
import requests

DD_URL = os.environ.get("DEFECTDOJO_URL")
DD_KEY = os.environ.get("DEFECTDOJO_API_KEY")
DD_PRODUCT = os.environ.get("DEFECTDOJO_PRODUCT_ID")
DD_ENG = os.environ.get("DEFECTDOJO_ENGAGEMENT_ID")

HEADERS = {"Authorization": f"Token {DD_KEY}"}
SEVERITY_MAP = {"BLOCKER": "Critical", "CRITICAL": "High", "MAJOR": "Medium", "MINOR": "Low", "INFO": "Info"}

def build_hash(*parts):
    joined = "|".join([str(p) for p in parts if p])
    return hashlib.sha256(joined.encode()).hexdigest()[:32]

def push_finding(finding_dict):
    try:
        r = requests.post(f"{DD_URL}/api/v2/findings/", headers=HEADERS, json=finding_dict, timeout=30)
        if r.status_code == 201:
            print(f"[OK] Created: {finding_dict.get('title')} Tags: {finding_dict.get('tags')}")
        else:
            print(f"[ERROR] {r.status_code}: {r.text}")
    except Exception as e:
        print(f"[CRITICAL] API Error: {e}")

def build_finding(issue, epss_lookup, is_hotspot=False):
    rule = issue.get("rule" if not is_hotspot else "ruleKey", "Unknown")
    msg = issue.get("message", "")
    comp = issue.get("component", "Unknown")
    severity = SEVERITY_MAP.get(issue.get("severity"), "Medium")
    
    tags = ["SonarQube"]
    # Hotspots are handled differently
    if is_hotspot: tags.append("Security-Hotspot")

    unique_hash = build_hash(rule, comp, msg)
    
    return {
        "title": f"[{'Hotspot' if is_hotspot else 'Sonar'}] {msg[:80]}",
        "severity": severity,
        "description": f"Rule: {rule}\nComponent: {comp}\nMessage: {msg}",
        "unique_id_from_tool": unique_hash,
        "product": DD_PRODUCT,
        "engagement": DD_ENG,
        "tags": tags,
        "active": True,
        "verified": False,
        "static_finding": True,
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--issues", required=True)
    parser.add_argument("--hotspots", required=True)
    parser.add_argument("--epss_results", required=False)
    args = parser.parse_args()

    # Load lookup if available (though Sonar rarely matches direct CVEs without plugins)
    epss_lookup = {}
    if args.epss_results and os.path.exists(args.epss_results):
        with open(args.epss_results) as f:
            epss_lookup = {item["cve"]: item for item in json.load(f).get("high_risk", [])}

    with open(args.issues) as f:
        for issue in json.load(f).get("issues", []):
            push_finding(build_finding(issue, epss_lookup))

    with open(args.hotspots) as f:
        for h in json.load(f).get("hotspots", []):
            push_finding(build_finding(h, epss_lookup, is_hotspot=True))

if __name__ == "__main__":
    main()