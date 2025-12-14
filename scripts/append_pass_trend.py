#!/usr/bin/env python3
"""
Append weekly ASVS PASS% trend (executive sparkline)

Input:
  - docs/data/governance/asvs-coverage.json

Output:
  - docs/data/trends/asvs-pass-trend.json

Behavior:
  - Append once per ISO week (YYYY-WW)
  - Idempotent (won't duplicate same week)
  - Audit-friendly, append-only
"""

from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone

ASVS_PATH = Path("docs/data/governance/asvs-coverage.json")
OUT_PATH = Path("docs/data/trends/asvs-pass-trend.json")


def iso_week_now() -> str:
    now = datetime.now(timezone.utc)
    year, week, _ = now.isocalendar()
    return f"{year}-W{week:02d}"


def read_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def main() -> None:
    if not ASVS_PATH.exists():
        raise SystemExit(f"[ERROR] Missing ASVS coverage: {ASVS_PATH}")

    asvs = read_json(ASVS_PATH, {})
    summary = asvs.get("summary", {})

    pass_pct = summary.get("coverage_percent")
    total = summary.get("total")

    if pass_pct is None:
        raise SystemExit("[ERROR] coverage_percent missing in ASVS summary")

    week = iso_week_now()

    trend = read_json(OUT_PATH, {
        "meta": {
            "metric": "asvs_pass_percent",
            "unit": "%",
            "source": "OWASP ASVS",
        },
        "data": []
    })

    # Prevent duplicate week
    if any(row.get("week") == week for row in trend["data"]):
        print(f"[INFO] Week {week} already recorded, skipping")
        return

    trend["data"].append({
        "week": week,
        "pass_percent": round(float(pass_pct), 2),
        "controls": total,
        "recorded_at": datetime.now(timezone.utc).isoformat()
    })

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(trend, indent=2), encoding="utf-8")

    print(f"[OK] Appended ASVS PASS% trend for {week}: {pass_pct}%")


if __name__ == "__main__":
    main()
