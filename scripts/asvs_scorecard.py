import json, glob
from collections import defaultdict

baseline = json.load(open("scripts/asvs_baseline.json"))
failed = defaultdict(set)

for path in glob.glob("security-reports/*.json"):
    try:
        data = json.load(open(path))
    except Exception:
        continue

    if not isinstance(data, list):
        continue

    for item in data:
        sev = item.get("severity", "").upper()
        asvs = item.get("asvs")

        if sev in ("HIGH", "CRITICAL") and asvs:
            domain = asvs.split(".")[0]
            failed[domain].add(asvs)

scorecard = {}

for k, v in baseline.items():
    fail_count = len(failed.get(k, []))
    scorecard[k] = {
        "name": v["name"],
        "total": v["total"],
        "failed": fail_count,
        "pass_pct": round((v["total"] - fail_count) / v["total"] * 100, 2)
    }

print(json.dumps(scorecard, indent=2))
