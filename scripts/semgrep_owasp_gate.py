#!/usr/bin/env python3
import json, sys

BLOCK_OWASP = {"A02", "A03"}
BLOCK_SEVERITY = {"ERROR", "CRITICAL"}

report = sys.argv[1]
data = json.load(open(report))

violations = []

for r in data.get("results", []):
    meta = r.get("extra", {}).get("metadata", {})
    owasp = set(o.split(":")[0] for o in meta.get("owasp", []))
    severity = r.get("extra", {}).get("severity", "").upper()

    if owasp & BLOCK_OWASP and severity in BLOCK_SEVERITY:
        violations.append((r["check_id"], list(owasp), severity))

if violations:
    print("❌ Semgrep OWASP Gate FAILED")
    for v in violations:
        print(v)
    open("security-reports/gate_failed", "w").write("semgrep")
    sys.exit(1)

print("✅ Semgrep OWASP Gate PASSED")
