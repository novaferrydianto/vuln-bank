#!/usr/bin/env python3
import json
from pathlib import Path

REPORT = Path("security-reports/epss-findings.json")
BASELINE = Path("security-baselines/epss-baseline.json")


def load(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text())


def main():
    current = load(REPORT)
    baseline = load(BASELINE)

    if not current:
        print("ℹ️ No current EPSS report")
        return

    cur_score = current.get("rollup", {}).get("portfolio_score_0_100", 0)

    if not baseline:
        print(f"🆕 No baseline found — current risk score **{cur_score}/100**")
        return

    base_score = baseline.get("rollup", {}).get("portfolio_score_0_100", 0)
    delta = round(cur_score - base_score, 2)

    if delta > 0:
        trend = "⬆️ Increased risk"
    elif delta < 0:
        trend = "⬇️ Reduced risk"
    else:
        trend = "➖ No change"

    print("📉 **Risk Delta vs Baseline**")
    print(f"- Baseline score: **{base_score}/100**")
    print(f"- PR score: **{cur_score}/100**")
    print(f"- Delta: **{delta}** ({trend})")


if __name__ == "__main__":
    main()
