#!/usr/bin/env python3
import json, sys, os, hashlib

BLOCK_OWASP = {"A02", "A03"}
BLOCK_SEVERITY = {"ERROR"}

def fingerprint(r):
    h = f"{r['check_id']}:{r['path']}:{r['start']['line']}"
    return hashlib.sha1(h.encode()).hexdigest()

# -------------------------
# Load current scan
# -------------------------
current = json.load(open(sys.argv[1]))

# -------------------------
# Load baseline (optional)
# -------------------------
baseline = {"results": []}
baseline_path = sys.argv[2] if len(sys.argv) > 2 else None

if baseline_path and os.path.exists(baseline_path):
    baseline = json.load(open(baseline_path))
else:
    print("[INFO] No baseline found – treating current findings as baseline")
    sys.exit(0)   # ⬅️ THIS IS THE KEY FIX

baseline_fp = {fingerprint(r) for r in baseline.get("results", [])}

# -------------------------
# Delta evaluation
# -------------------------
violations = []

for r in current.get("results", []):
    meta = r.get("extra", {}).get("metadata", {})
    owasp = {o.split(":")[0] for o in meta.get("owasp", [])}
    severity = r.get("extra", {}).get("severity", "").upper()

    if owasp & BLOCK_OWASP and severity in BLOCK_SEVERITY:
        fp = fingerprint(r)
        if fp not in baseline_fp:
            violations.append((r["check_id"], list(owasp), severity))

# -------------------------
# Gate decision
# -------------------------
if violations:
    print("❌ NEW OWASP violations introduced")
    for v in violations:
        print(v)
    sys.exit(1)

print("✅ Semgrep OWASP delta gate passed")
