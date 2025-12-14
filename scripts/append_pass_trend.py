#!/usr/bin/env python3
"""
Append weekly ASVS PASS / FAIL / KEV trend (append-only)

Output:
security-metrics/weekly/pass-trend.json
"""

import json
from pathlib import Path
from datetime import datetime, timezone

COVERAGE = Path("docs/data/governance/asvs-coverage.json")
EPSS = Path("docs/data/epss-findings.json")
OUT = Path("security-metrics/weekly/pass-trend.json")

OUT.parent.mkdir(parents=True, exist_ok=True)

def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")

def main():
    cov = json.loads(COVERAGE.read_text())
    summ = cov["summary"]

    total = summ.get("total", 0)
    passed = summ.get("passed", 0)
    na = summ.get("not_applicable", 0)
    failed = max(total - passed - na, 0)

    pass_pct = round((passed / total) * 100) if total else 0

    kev_count = 0
    if EPSS.exists():
        epss = json.loads(EPSS.read_text())
        kev_count = sum(1 for v in epss.get("high_risk", []) if v.get("is_kev"))

    record = {
        "date": utc_now(),
        "pass_percent": pass_pct,
        "fail_count": failed,
        "kev_count": kev_count,
    }

    history = []
    if OUT.exists():
        history = json.loads(OUT.read_text())

        # avoid duplicate week
        if history and history[-1]["date"] == record["date"]:
            print("[INFO] Trend already recorded for this week")
            return

    history.append(record)
    OUT.write_text(json.dumps(history, indent=2))
    print(f"[OK] Weekly trend appended: {record}")

if __name__ == "__main__":
    main()
