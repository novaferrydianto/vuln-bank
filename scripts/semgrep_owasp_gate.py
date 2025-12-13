#!/usr/bin/env python3
import json, sys, hashlib

BLOCK_OWASP = {"A02", "A03"}
BLOCK_SEVERITY = {"ERROR"}

def fingerprint(r):
    h = f"{r['check_id']}:{r['path']}:{r['start']['line']}"
    return hashlib.sha1(h.encode()).hexdigest()

current = json.load(open(sys.argv[1]))

baseline_file = "security-reports/semgrep-baseline.json"
baseline = {"results": []}

if len(sys.argv) == 3:
    baseline = json.load(open(sys.argv[2]))

baseline_fp = {fingerprint(r) for r in baseline.get("results", [])}

violations = []

for r in current.get("results", []):
    meta = r.get("extra", {}).get("metadata", {})
    owasp = {o.split(":")[0] for o in meta.get("owasp", [])}
    severity = r.get("extra", {}).get("severity", "").upper()

    if owasp & BLOCK_OWASP and severity in BLOCK_SEVERITY:
        fp = fingerprint(r)
        if fp not in baseline_fp:
            violations.append((r["check_id"], list(owasp), severity))

if violations:
    print("❌ NEW OWASP violations introduced")
    for v in violations:
        print(v)
    sys.exit(1)

print("✅ No new OWASP A02/A03 issues")
