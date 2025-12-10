#!/usr/bin/env python3
import json
import sys
from pathlib import Path

ZAP_JSON = Path(sys.argv[1])
THRESHOLD = sys.argv[2].upper()

OUT_DIR = Path("security-reports")
IGNORE_FILE = Path("security-policies/zap_ignore_alerts.json")

SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
THRESH_VAL = SEV_ORDER.get(THRESHOLD, 3)

# --------------------------------------------------
# Load ignore list
# --------------------------------------------------
ignored_alerts = set()
if IGNORE_FILE.exists():
    ignored_alerts = set(json.loads(IGNORE_FILE.read_text()))

if not ZAP_JSON.exists():
    print("[WARN] ZAP JSON not found, skipping gate")
    sys.exit(0)

data = json.loads(ZAP_JSON.read_text())
sites = data.get("site", [])
alerts = sites[0].get("alerts", []) if sites else []

violations = []

for a in alerts:
    alert_name = a.get("alert")

    if alert_name in ignored_alerts:
        continue

    risk = (a.get("riskdesc", "") or "").upper()
    sev = (
        "HIGH" if "HIGH" in risk else
        "MEDIUM" if "MEDIUM" in risk else
        "LOW"
    )

    if SEV_ORDER.get(sev, 0) >= THRESH_VAL:
        violations.append({
            "alert": alert_name,
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
