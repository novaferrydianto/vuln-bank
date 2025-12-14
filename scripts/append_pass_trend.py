#!/usr/bin/env python3
"""
Append weekly ASVS PASS% trend for executive dashboards.
Append-only, safe for GitHub Pages.
"""

import json
from datetime import datetime
from pathlib import Path

TREND_FILE = Path("docs/data/trends/asvs-pass-trend.json")
ASVS_FILE  = Path("docs/data/governance/asvs-coverage.json")

def iso_week():
    now = datetime.utcnow()
    return f"{now.isocalendar().year}-W{now.isocalendar().week:02d}"

def main():
    if not ASVS_FILE.exists():
        raise SystemExit("ASVS coverage not found")

    asvs = json.loads(ASVS_FILE.read_text())
    summary = asvs.get("summary", {})

    entry = {
        "week": iso_week(),
        "pass_pct": int(summary.get("coverage_percent", 0)),
        "fail": int(summary.get("fail", 0)),
        "kev": int(summary.get("kev", 0)),
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }

    TREND_FILE.parent.mkdir(parents=True, exist_ok=True)

    history = []
    if TREND_FILE.exists():
        history = json.loads(TREND_FILE.read_text())

        # Prevent duplicate week
        if history and history[-1]["week"] == entry["week"]:
            history[-1] = entry
        else:
            history.append(entry)
    else:
        history = [entry]

    TREND_FILE.write_text(json.dumps(history, indent=2))
    print(f"[OK] Trend appended: {entry['week']} PASS={entry['pass_pct']}%")

if __name__ == "__main__":
    main()
