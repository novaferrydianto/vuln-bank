#!/usr/bin/env python3
import os, json, datetime, requests

DD_URL = os.environ["DEFECTDOJO_URL"]
API_KEY = os.environ["DEFECTDOJO_API_KEY"]

HEADERS = {
    "Authorization": f"Token {API_KEY}",
    "Accept": "application/json"
}

SLA = {
    "Critical": 7,
    "High": 14,
    "Medium": 30
}

resp = requests.get(
    f"{DD_URL}/api/v2/findings/?active=true&limit=1000",
    headers=HEADERS,
    timeout=30
)
data = resp.json()["results"]

now = datetime.datetime.utcnow()

total = 0
breached = 0

for f in data:
    sev = f.get("severity")
    if sev not in SLA:
        continue

    created = datetime.datetime.fromisoformat(
        f["date"].replace("Z", "")
    )
    age = (now - created).days

    total += 1
    if age > SLA[sev]:
        breached += 1

out = {
    "generated_at": now.isoformat() + "Z",
    "total_findings": total,
    "sla_breached": breached,
    "breach_rate": round((breached / total) * 100, 2) if total else 0
}

os.makedirs("docs/data", exist_ok=True)
with open("docs/data/defectdojo-sla-weekly.json", "w") as f:
    json.dump(out, f, indent=2)

print("[OK] DefectDojo SLA weekly report generated")
