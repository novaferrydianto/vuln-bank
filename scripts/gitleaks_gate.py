#!/usr/bin/env python3
import json
import sys
from pathlib import Path

REPORT = Path("security-reports/gitleaks.sarif")

if not REPORT.exists():
    print("[INFO] No gitleaks SARIF found → skipping gate")
    sys.exit(0)

data = json.loads(REPORT.read_text())
runs = data.get("runs", [])
results = runs[0].get("results", []) if runs else []

violations = []

for r in results:
    level = (r.get("level") or "").upper()
    rule = r.get("ruleId")

    if level in ("ERROR", "WARNING"):
        violations.append({
            "rule": rule,
            "level": level,
            "message": r.get("message", {}).get("text"),
        })

if violations:
    print("[GATE] 🚨 Secret gate FAILED")
    for v in violations:
        print(f"- {v['level']} | {v['rule']} | {v['message']}")
    sys.exit(1)

print("[GATE] ✅ Secret gate PASSED")
