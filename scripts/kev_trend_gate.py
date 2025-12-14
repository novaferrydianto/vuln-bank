#!/usr/bin/env python3
"""
KEV Trend Gate
Fail if KEV count increases for N consecutive weeks (default=2)
"""

import json
import sys
from pathlib import Path

TREND_FILE = Path("security-metrics/weekly/asvs-pass-trend.json")
CONSECUTIVE_WEEKS = 2


def main():
    if not TREND_FILE.exists():
        print("[INFO] No KEV trend file, skipping gate")
        return 0

    data = json.loads(TREND_FILE.read_text())
    if len(data) < CONSECUTIVE_WEEKS + 1:
        print("[INFO] Not enough data points for KEV trend gate")
        return 0

    kev_series = [x.get("kev_count", 0) for x in data[-(CONSECUTIVE_WEEKS + 1):]]

    increasing = all(
        kev_series[i] > kev_series[i - 1]
        for i in range(1, len(kev_series))
    )

    if increasing:
        print("❌ KEV TREND GATE FAILED")
        print(f"KEV increased for {CONSECUTIVE_WEEKS} consecutive weeks:")
        print(" → ".join(map(str, kev_series)))
        Path("security-reports/gate_failed").touch()
        return 1

    print("✅ KEV trend stable or improving")
    return 0


if __name__ == "__main__":
    sys.exit(main())
