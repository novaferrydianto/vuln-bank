#!/usr/bin/env python3
import os, json, datetime, urllib.request, urllib.parse

DD_URL = os.environ["DEFECTDOJO_URL"].rstrip("/")
DD_TOKEN = os.environ["DEFECTDOJO_API_KEY"]
PRODUCT_ID = os.environ.get("DEFECTDOJO_PRODUCT_ID", "").strip()

# SLA days (edit as you like)
SLA_DAYS = {
  "Critical": 7,
  "High": 14,
  "Medium": 30,
  "Low": 90,
  "Info": 180,
}

HEADERS = {
  "Authorization": f"Token {DD_TOKEN}",
  "Accept": "application/json",
  "User-Agent": "vuln-bank-sla-weekly"
}

NOW = datetime.datetime.utcnow()

def dd_get(path, params=None):
  qs = ""
  if params:
    qs = "?" + urllib.parse.urlencode(params)
  url = f"{DD_URL}{path}{qs}"
  req = urllib.request.Request(url, headers=HEADERS)
  with urllib.request.urlopen(req, timeout=30) as r:
    return json.load(r)

def parse_dt(s):
  if not s:
    return None
  # DefectDojo typically uses ISO-8601 with timezone
  # Example: 2025-12-13T20:49:57.638Z or +00:00
  s = s.replace("Z", "+00:00")
  try:
    return datetime.datetime.fromisoformat(s)
  except Exception:
    return None

def severity_norm(raw):
  r = (raw or "").strip().capitalize()
  # normalize common variants
  if r in ("Critical","High","Medium","Low","Info"):
    return r
  if r.lower() == "informational":
    return "Info"
  return "Medium"

def fetch_findings():
  page = 1
  results = []
  while True:
    params = {
      "active": "true",
      "mitigated": "false",
      "false_p": "false",
      "duplicate": "false",
      "out_of_scope": "false",
      "limit": 200,
      "offset": (page - 1) * 200,
    }
    if PRODUCT_ID:
      params["test__engagement__product"] = PRODUCT_ID  # works on many DD versions
      # if your DD uses "product", switch to: params["product"] = PRODUCT_ID

    data = dd_get("/api/v2/findings/", params=params)
    batch = data.get("results", []) or []
    results.extend(batch)

    if data.get("next"):
      page += 1
      continue
    break
  return results

findings = fetch_findings()

breaches = []
by_sev = {k: {"open": 0, "breach": 0} for k in SLA_DAYS.keys()}

for f in findings:
  sev = severity_norm(f.get("severity"))
  created = parse_dt(f.get("date") or f.get("created") or f.get("created_at"))
  if not created:
    continue

  age_days = (NOW - created).days
  sla = int(SLA_DAYS.get(sev, 30))

  by_sev.setdefault(sev, {"open": 0, "breach": 0})
  by_sev[sev]["open"] += 1

  is_breach = age_days > sla
  if is_breach:
    by_sev[sev]["breach"] += 1
    breaches.append({
      "id": f.get("id"),
      "title": f.get("title") or f.get("finding_title") or "Untitled",
      "severity": sev,
      "age_days": age_days,
      "sla_days": sla,
      "created": created.isoformat(),
      "url": f"{DD_URL}/finding/{f.get('id')}" if f.get("id") else DD_URL,
      "cwe": f.get("cwe"),
      "epss": f.get("epss_score"),  # if your DD stores it (optional)
    })

# sort: worst first
breaches.sort(key=lambda x: (["Critical","High","Medium","Low","Info"].index(x["severity"]) if x["severity"] in ["Critical","High","Medium","Low","Info"] else 2,
                            -x["age_days"]))

result = {
  "generated_at": NOW.isoformat() + "Z",
  "product_id": PRODUCT_ID or None,
  "sla_days": SLA_DAYS,
  "summary": by_sev,
  "breaches_top": breaches[:50],  # keep dashboard small
  "breach_count": len(breaches),
}

# paths
os.makedirs("security-metrics/weekly", exist_ok=True)
os.makedirs("docs/data", exist_ok=True)

with open("docs/data/sla-latest.json", "w") as f:
  json.dump(result, f, indent=2)

with open("docs/data/sla-history.jsonl", "a") as f:
  f.write(json.dumps(result) + "\n")

with open("security-metrics/weekly/sla-latest.json", "w") as f:
  json.dump(result, f, indent=2)

print("[OK] SLA weekly breach report generated:", len(breaches))
