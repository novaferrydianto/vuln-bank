#!/usr/bin/env python3
import json
import glob
from collections import defaultdict
from pathlib import Path

BASELINE_PATH = Path("scripts/asvs_baseline.json")
REPORT_PATHS = [Path("security-reports/normalized.json")] + list(
    Path("security-reports").glob("*.json")
)

baseline = json.loads(BASELINE_PATH.read_text())

failed = defaultdict(lambda: {"controls": set(), "sources": set()})

def normalize_asvs(asvs):
    """
    Normalize ASVS field into list of controls
    """
    if not asvs:
        return []

    if isinstance(asvs, str):
        return [asvs]

    if isinstance(asvs, dict):
        return [asvs.get("control")] if asvs.get("control") else []

    if isinstance(asvs, list):
        return asvs

    return []

for path in REPORT_PATHS:
    try:
        data = json.loads(path.read_text())
    except Exception:
        continue

    items = data.get("findings", []) if isinstance(data, dict) else data
    if not isinstance(items, list):
        continue

    for item in items:
        sev = (item.get("severity") or "").upper()
        if sev not in ("HIGH", "CRITICAL"):
            continue

        if item.get("baseline") is True:
            continue  # ✅ respect accepted risk

        asvs_controls = normalize_asvs(item.get("asvs"))
        for control in asvs_controls:
            domain = control.split(".")[0]
            failed[domain]["controls"].add(control)
            failed[domain]["sources"].add(item.get("source", "unknown"))

# Build scorecard
scorecard = {}
non_compliant = False

for domain, meta in baseline.items():
    total = meta["total"]
    failed_controls = failed.get(domain, {}).get("controls", set())
    failed_count = len(failed_controls)

    passed = max(total - failed_count, 0)
    pass_pct = round((passed / total) * 100, 2) if total else 100.0

    if failed_count > 0 and domain in ("V2", "V4"):
        non_compliant = True  # ASVS Level 2 breaker

    scorecard[domain] = {
        "name": meta["name"],
        "total": total,
        "failed": failed_count,
        "failed_controls": sorted(failed_controls),
        "sources": sorted(failed.get(domain, {}).get("sources", [])),
        "pass_pct": pass_pct,
    }

output = {
    "level": "ASVS Level 2",
    "compliant": not non_compliant,
    "scorecard": scorecard,
}

print(json.dumps(output, indent=2))
