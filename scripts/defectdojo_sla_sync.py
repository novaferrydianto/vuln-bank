import os, json, datetime, urllib.request

BASE = os.environ["DEFECTDOJO_URL"].rstrip("/")
TOKEN = os.environ["DEFECTDOJO_API_KEY"]

HEADERS = {
    "Authorization": f"Token {TOKEN}",
    "Accept": "application/json"
}

NOW = datetime.datetime.utcnow()

def get_findings():
    url = f"{BASE}/api/v2/findings/?active=true&limit=500"
    req = urllib.request.Request(url, headers=HEADERS)
    return json.load(urllib.request.urlopen(req))["results"]

breaches = []

for f in get_findings():
    sev = f["severity"]
    created = datetime.datetime.fromisoformat(f["date"].replace("Z",""))
    age_days = (NOW - created).days

    sla = {"Critical": 7, "High": 14}.get(sev)
    if sla and age_days > sla:
        breaches.append({
            "title": f["title"],
            "severity": sev,
            "age_days": age_days,
            "sla_days": sla
        })

out = {
    "generated_at": NOW.isoformat() + "Z",
    "breaches": breaches
}

os.makedirs("security-metrics/weekly", exist_ok=True)
with open("security-metrics/weekly/defectdojo-sla.json", "w") as f:
    json.dump(out, f, indent=2)

print(f"[OK] SLA breaches: {len(breaches)}")
