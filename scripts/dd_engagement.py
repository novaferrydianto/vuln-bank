#!/usr/bin/env python3
"""
Create DefectDojo Engagement for this pipeline run.

Environment Variables:
  DEFECTDOJO_URL
  DEFECTDOJO_API_KEY
  DEFECTDOJO_PRODUCT_ID
  DEFECTDOJO_ENGAGEMENT_NAME  (e.g., Build-123)
"""

import os
import json
import requests
from datetime import datetime

DD_URL = os.getenv("DEFECTDOJO_URL", "").rstrip("/")
DD_API_KEY = os.getenv("DEFECTDOJO_API_KEY", "")
DD_PRODUCT_ID = os.getenv("DEFECTDOJO_PRODUCT_ID", "")
ENGAGEMENT_NAME = os.getenv("DEFECTDOJO_ENGAGEMENT_NAME", "Build")

API = f"{DD_URL}/api/v2"

headers = {
    "Authorization": f"Token {DD_API_KEY}",
}

def create_engagement():
    payload = {
        "name": ENGAGEMENT_NAME,
        "description": f"Automated CI engagement for {ENGAGEMENT_NAME}",
        "product": int(DD_PRODUCT_ID),
        "status": "In Progress",
        "target_start": datetime.utcnow().strftime("%Y-%m-%d"),
        "target_end": datetime.utcnow().strftime("%Y-%m-%d"),
        "engagement_type": "CI/CD",
        "tags": ["pipeline", "github-actions", "auto"],
        "build_id": ENGAGEMENT_NAME,
        "commit_hash": os.getenv("GITHUB_SHA"),
        "branch_tag": os.getenv("GITHUB_REF_NAME"),
        "deduplication_on_engagement": True,
    }

    print(f"[DD] Creating engagement: {ENGAGEMENT_NAME}")
    r = requests.post(f"{API}/engagements/", json=payload, headers=headers)
    if r.status_code not in (200, 201):
        print(f"[DD] Engagement creation failed: {r.text}")
        return None

    engagement = r.json()
    engagement_id = engagement.get("id")
    print(f"[DD] Engagement created: {engagement_id}")
    return engagement_id

if __name__ == "__main__":
    create_engagement()
