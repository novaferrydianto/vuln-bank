#!/usr/bin/env python3
import json
from pathlib import Path

PR = Path("security-reports/epss-findings.json")
BASE = Path("security-baselines/epss-baseline.json")

def load(p):
    return {f["cve"]: f for f in json.load(open(p))["high_risk"]} if p.exists() else {}

pr = load(PR)
base = load(BASE)

new = set(pr) - set(base)
resolved = set(base) - set(pr)

print("## 📊 Risk Delta")
print(f"- 🔴 New exploitable risks: {len(new)}")
print(f"- 🟢 Resolved risks: {len(resolved)}")

if new:
    print("\n### 🔴 New High-Risk CVEs")
    for cve in sorted(new):
        f = pr[cve]
        print(f"- `{cve}` EPSS={f['epss']:.2f} KEV={f['is_kev']}")
