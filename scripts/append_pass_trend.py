#!/usr/bin/env python3
"""
Append weekly ASVS PASS percentage to trend history.

Input:
  - docs/data/governance/asvs-coverage.json

Output:
  - docs/data/trends/asvs-pass-weekly.json

Safe to run weekly (idempotent per week).
"""

from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone


ASVS_INPUT = Path("docs/data/governance/asvs-coverage.json")
TREND_OUT  = Path("docs/data/trends/asvs-pass-weekly.json")


def current_week() -> str:
    # ISO week anchor (Monday)
    now = datetime.now(timezone.utc)
    year, week, _ = now.isocalendar()
    return f"{year}-W{week:02d}"


def load_json(p: Path, default):
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default


def main():
    if not ASVS_INPUT.exists():
        raise SystemExit(f"[ERROR] Missing {ASVS_INPUT}")

    asvs = load_json(ASVS_INPUT, {})
    summary = asvs.get("summary", {})

    pass_pct = summary.get("coverage_percent")
    if pass_pct is None:
        raise SystemExit("[ERROR] coverage_percent not found in ASVS summary")

    week = current_week()

    trend = load_json(TREND_OUT, {"series": []})
    series = trend.get("series", [])

    # remove existing entry for same week (idempotent)
    series = [x for x in series if x.get("week") != week]

    series.append({
        "week": week,
        "pass_percent": int(round(pass_pct))
    })

    # keep sorted
    series = sorted(series, key=lambda x: x["week"])

    TREND_OUT.parent.mkdir(parents=True, exist_ok=True)
    TREND_OUT.write_text(
        json.dumps({"series": series}, indent=2),
        encoding="utf-8"
    )

    print(f"[OK] ASVS PASS trend appended: week={week}, pass={pass_pct}%")


if __name__ == "__main__":
    main()
