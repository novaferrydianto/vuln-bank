#!/usr/bin/env python3
import os, json, datetime, urllib.request, urllib.parse

DEFECTDOJO_URL = os.environ.get("DEFECTDOJO_URL", "").rstrip("/")
DEFECTDOJO_API_KEY = os.environ.get("DEFECTDOJO_API_KEY", "")
PRODUCT_ID = os.environ.get("DEFECTDOJO_PRODUCT_ID")  # optional

# SLA policy (days) - default can be adjusted via env
SLA_CRITICAL_DAYS = int(os.environ.get("SLA_CRITICAL_DAYS", "7"))
SLA_HIGH_DAYS = int(os.environ.get("SLA_HIGH_DAYS", "30"))

# How many days back to consider "weekly window" for reporting
WINDOW_DAYS = int(os.environ.get("WINDOW_DAYS", "7"))

OUT_DOCS = os.environ.get("OUT_DOCS", "docs/data/defectdojo-sla-weekly.json")
OUT_METRICS = os.environ.get("OUT_METRICS", "security-metrics/weekly/defectdojo-sla-weekly.json")

if not DEFECTDOJO_URL or not DEFECTDOJO_API_KEY:
    print("[SKIP] DEFECTDOJO_URL / DEFECTDOJO_API_KEY not set")
    raise SystemExit(0)

HEADERS = {
    "Authorization": f"Token {DEFECTDOJO_API_KEY}",
    "Accept": "application/json",
    "User-Agent": "vuln-bank-sla-weekly"
}

NOW = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
WINDOW_START = NOW - datetime.timedelta(days=WINDOW_DAYS)

def parse_dt(s: str):
    if not s:
        return None
    # DefectDojo commonly uses ISO 8601 with Z or timezone offset
    try:
        if s.endswith("Z"):
            return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
        return datetime.datetime.fromisoformat(s)
    except Exception:
        return None

def infer_asset(tags, title="", file_path="", component_name="", endpoints=None):
    """
    Priority:
      1) tag: asset:frontend|asset:backend|asset:db
      2) heuristics from file_path/component/title/endpoints
    """
    tags = tags or []
    for t in tags:
        t_low = str(t).strip().lower()
        if t_low.startswith("asset:"):
            v = t_low.split("asset:", 1)[1].strip()
            if v in ("frontend", "backend", "db"):
                return v

    hay = " ".join([
        str(title or ""),
        str(file_path or ""),
        str(component_name or ""),
        " ".join([str(e) for e in (endpoints or [])])
    ]).lower()

    # Heuristics
    if any(k in hay for k in ["frontend", "ui", "web", "client", "react", "next", "nuxt", "templates", "static/", "docs/"]):
        return "frontend"
    if any(k in hay for k in ["postgres", "mysql", "db", "database", "sql", "migration", "schema"]):
        return "db"
    return "backend"

def dd_get(path, params=None):
    qs = ""
    if params:
        qs = "?" + urllib.parse.urlencode(params)
    url = f"{DEFECTDOJO_URL}{path}{qs}"
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)

def fetch_findings(severity: str):
    """
    Fetch findings page-by-page.
    Filter: active, not mitigated, not false positive, not duplicate
    """
    results = []
    offset = 0
    limit = 200

    while True:
        params = {
            "limit": limit,
            "offset": offset,
            "severity": severity,
            "active": "true",
            "mitigated": "false",
            "false_p": "false",
            "duplicate": "false",
        }
        if PRODUCT_ID:
            params["test__engagement__product"] = PRODUCT_ID

        data = dd_get("/api/v2/findings/", params=params)
        chunk = data.get("results", []) or []
        results.extend(chunk)

        next_url = data.get("next")
        if not next_url:
            break
        offset += limit

    return results

def age_days(created_dt):
    if not created_dt:
        return None
    delta = NOW - created_dt
    return int(delta.total_seconds() // 86400)

def is_breach(sev, age):
    if age is None:
        return False
    if sev == "Critical":
        return age > SLA_CRITICAL_DAYS
    if sev == "High":
        return age > SLA_HIGH_DAYS
    return False

def touched_this_week(created_dt, last_status_update_dt):
    # Consider it "in weekly report" if created or updated within WINDOW_DAYS
    for dt in [created_dt, last_status_update_dt]:
        if dt and dt >= WINDOW_START:
            return True
    return False

def main():
    severities = ["Critical", "High"]
    breaches = {s: 0 for s in severities}
    breaches_by_asset = {a: {s: 0 for s in severities} for a in ["frontend", "backend", "db"]}

    sampled = []  # small list for top breaches
    total_considered = 0

    for sev in severities:
        findings = fetch_findings(sev)
        for f in findings:
            created = parse_dt(f.get("created"))
            last_status_update = parse_dt(f.get("last_status_update")) or parse_dt(f.get("modified"))
            if not touched_this_week(created, last_status_update):
                continue

            total_considered += 1
            a = age_days(created)
            if is_breach(sev, a):
                breaches[sev] += 1
                tags = f.get("tags") or []
                asset = infer_asset(
                    tags=tags,
                    title=f.get("title") or "",
                    file_path=f.get("file_path") or "",
                    component_name=f.get("component_name") or "",
                    endpoints=f.get("endpoints") or []
                )
                breaches_by_asset[asset][sev] += 1

                sampled.append({
                    "id": f.get("id"),
                    "severity": sev,
                    "age_days": a,
                    "title": f.get("title"),
                    "asset": asset,
                    "created": f.get("created"),
                    "url": f"{DEFECTDOJO_URL}/finding/{f.get('id')}"
                })

    # Sort sampled by severity then age desc
    sev_rank = {"Critical": 2, "High": 1}
    sampled.sort(key=lambda x: (sev_rank.get(x["severity"], 0), x.get("age_days", 0)), reverse=True)

    out = {
        "generated_at": NOW.isoformat().replace("+00:00", "Z"),
        "window_days": WINDOW_DAYS,
        "sla_days": {"Critical": SLA_CRITICAL_DAYS, "High": SLA_HIGH_DAYS},
        "counts": {
            "considered": total_considered,
            "breaches": breaches,
            "breaches_by_asset": breaches_by_asset
        },
        "top_breaches": sampled[:10]
    }

    # write outputs
    for p in [OUT_DOCS, OUT_METRICS]:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)

    print("[OK] DefectDojo SLA weekly breach report generated")
    print(f" - {OUT_DOCS}")
    print(f" - {OUT_METRICS}")

if __name__ == "__main__":
    main()
