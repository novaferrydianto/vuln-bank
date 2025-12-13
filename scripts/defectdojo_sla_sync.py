import requests, datetime, os

BASE = os.environ["DEFECTDOJO_URL"]
TOKEN = os.environ["DEFECTDOJO_API_KEY"]

headers = {
  "Authorization": f"Token {TOKEN}",
  "Accept": "application/json"
}

r = requests.get(f"{BASE}/api/v2/findings/?active=true", headers=headers)
findings = r.json()["results"]

now = datetime.datetime.utcnow()

for f in findings:
    sev = f["severity"]
    created = datetime.datetime.fromisoformat(f["date"].replace("Z",""))

    sla_days = {"Critical":7,"High":14,"Medium":30}.get(sev)
    if not sla_days:
        continue

    if (now - created).days > sla_days:
        requests.patch(
            f"{BASE}/api/v2/findings/{f['id']}/",
            headers=headers,
            json={"sla_expiration": "Breached"}
        )
