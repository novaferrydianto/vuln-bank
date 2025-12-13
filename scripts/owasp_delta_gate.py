#!/usr/bin/env python3
"""
Block PR if OWASP A01 / A02 newly introduced
Based on ASVS export + baseline
"""

import json, sys, os
from pathlib import Path

BLOCK_OWASP = {"OWASP-A01-Broken-Access-Control", "OWASP-A02-Broken-Authentication"}

def load(p):
    return json.loads(Path(p).read_text()) if Path(p).exists() else {}

cur = load("security-reports/governance/asvs-coverage.json")
base = load("security-baselines/asvs-baseline.json")

cur_labels = set(cur.get("owasp_labels", []))
base_labels = set(base.get("owasp_labels", []))

introduced = (cur_labels - base_labels) & BLOCK_OWASP

if introduced:
    print("❌ BLOCKED: New critical OWASP category introduced:")
    for l in introduced:
        print(f" - {l}")
    Path("security-reports/gate_failed").write_text("OWASP critical regression")
    sys.exit(1)

print("✅ OWASP delta gate passed")
