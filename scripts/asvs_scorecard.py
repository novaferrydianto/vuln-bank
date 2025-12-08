import json, glob
from collections import defaultdict

baseline = json.load(open("scripts/asvs_baseline.json"))
failed = defaultdict(set)

paths = ["security-reports/normalized.json"] + glob.glob("security-reports/*.json")

for path in paths:
    try:
        data = json.load(open(path))
    except Exception:
        continue

    if isinstance(data, dict) and "findings" in data:
        items = data["findings"]
    elif isinstance(data, list):
        items = data
    else:
        continue

    for item in items:
        sev = (item.get("severity") or "").upper()
        asvs = item.get("asvs")

        if sev not in ("HIGH", "CRITICAL"):
            continue

        if isinstance(asvs, dict):
            asvs_id = asvs.get("control")
        else:
            asvs_id = asvs

        if not asvs_id:
            continue

        domain = asvs_id.split(".")[0]
        failed[domain].add(asvs_id)

scorecard = {}

for k, v in baseline.items():
    total = v["total"]
    fail_count = len(failed.get(k, []))
    passed = max(total - fail_count, 0)

    scorecard[k] = {
        "name": v["name"],
        "total": total,
        "failed": fail_count,
        "pass_pct": round((passed / total) * 100, 2) if total else 100.0
    }

print(json.dumps(scorecard, indent=2))
