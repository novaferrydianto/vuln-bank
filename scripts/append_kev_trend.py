#!/usr/bin/env python3
import json
import argparse
from datetime import date
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--epss", required=True)
ap.add_argument("--out", required=True)
args = ap.parse_args()

epss = json.load(open(args.epss))
out = Path(args.out)

week = date.today().isoformat()

kev = [
    f["cve"]
    for f in epss.get("high_risk", [])
    if f.get("is_kev") is True
]

entry = {
    "week": week,
    "kev_count": len(kev),
    "top_cves": kev[:3]
}

history = []
if out.exists():
    history = json.load(open(out))

history.append(entry)

out.parent.mkdir(parents=True, exist_ok=True)
json.dump(history, open(out, "w"), indent=2)

print(f"[OK] KEV trend appended: {entry}")
