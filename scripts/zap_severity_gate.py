#!/usr/bin/env python3
import json
import sys
from pathlib import Path

ZAP_JSON = Path(sys.argv[1])
THRESHOLD = sys.argv[2].upper()
OUT_DIR = Path("security-reports")

SEV_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
THRESH_VAL = SEV_ORDER.get(THRESHOLD, 3)

if not ZAP_JSON.exists():
    print("[WARN] ZAP JSON not found, skipping gate")
    sys.exit(0)

data = json.loads(ZAP_JSON.read_text())
alerts = data.get("site", [])[0].get("alerts", [])

violations = []

for a in alerts:
    sev_raw = (a.get("risk") or "").upper()
    sev = "HIGH" if sev_raw == "HIGH" else "MEDIUM" if sev_raw == "MEDIUM" else "LOW"

    if SEV_ORDER.get(sev, 0) >= THRESH_VAL:
        violations.append({
            "alert": a.get("alert"),
            "severity": sev,
            "instances": len(a.get("instances", []))
        })

if violations:
    gate = OUT_DIR / "zap_gate_failed"
    gate.write_text(
        f"ZAP gate failed ({len(violations)} findings >= {THRESHOLD})\n"
    )

    print("[GATE] 🚨 ZAP Severity Gate FAILED")
    for v in violations:
        print(f"- {v['severity']} | {v['alert']} ({v['instances']} hits)")
    sys.exit(1)

print("[GATE] ✅ ZAP Severity Gate PASSED")
