#!/usr/bin/env python3
"""
Append weekly ASVS risk trend (burn-down source of truth)
"""

import json
import argparse
from pathlib import Path
from datetime import datetime

def week_id():
    return datetime.utcnow().strftime("%Y-W%U")

def load(path):
    if path.exists():
        return json.loads(path.read_text())
    return {"points": []}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--asvs", required=True)
    p.add_argument("--out", required=True)
    args = p.parse_args()

    asvs = json.loads(Path(args.asvs).read_text())
    risk_raw = asvs["summary"]["risk"]["raw_score"]

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    trend = load(out)
    w = week_id()

    # idempotent per week
    trend["points"] = [p for p in trend["points"] if p["week"] != w]
    trend["points"].append({
        "week": w,
        "risk_raw": risk_raw
    })

    trend["points"] = trend["points"][-26:]  # ~6 months

    out.write_text(json.dumps(trend, indent=2))
    print(f"[OK] risk trend updated → {out}")

if __name__ == "__main__":
    main()
