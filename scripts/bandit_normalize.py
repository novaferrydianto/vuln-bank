#!/usr/bin/env python3
import json
import sys
from pathlib import Path

INPUT = Path(sys.argv[1])
OUTPUT = Path(sys.argv[2])

# -------------------------------
# Bandit → OWASP / ASVS Mapping
# -------------------------------
BANDIT_MAP = {
    "B102": {"owasp": "A05:2021-Security Misconfiguration", "asvs": ["V14.2"]},
    "B105": {"owasp": "A02:2021-Cryptographic Failures", "asvs": ["V7.1"]},
    "B106": {"owasp": "A02:2021-Cryptographic Failures", "asvs": ["V7.1"]},
    "B107": {"owasp": "A02:2021-Cryptographic Failures", "asvs": ["V7.1"]},
    "B201": {"owasp": "A03:2021-Injection", "asvs": ["V5.3"]},
    "B301": {"owasp": "A03:2021-Injection", "asvs": ["V5.3"]},
    "B501": {"owasp": "A05:2021-Security Misconfiguration", "asvs": ["V14.4"]},
    "B506": {"owasp": "A02:2021-Cryptographic Failures", "asvs": ["V7.2"]},
    "B602": {"owasp": "A05:2021-Security Misconfiguration", "asvs": ["V14.1"]},
    "B605": {"owasp": "A03:2021-Injection", "asvs": ["V5.3"]},
    "B607": {"owasp": "A03:2021-Injection", "asvs": ["V5.3"]},
}

# -------------------------------
# Load Bandit
# -------------------------------
data = json.loads(INPUT.read_text())
results = data.get("results", [])

findings = []

for r in results:
    test_id = r.get("test_id")
    mapping = BANDIT_MAP.get(test_id, {})

    findings.append({
        "title": r.get("issue_text"),
        "severity": r.get("issue_severity", "LOW").upper(),
        "confidence": r.get("issue_confidence"),
        "file": r.get("filename"),
        "line": r.get("line_number"),
        "tool": "bandit",
        "test_id": test_id,
        "owasp": mapping.get("owasp", "A05:2021-Security Misconfiguration"),
        "asvs": mapping.get("asvs", []),
    })

OUTPUT.write_text(json.dumps({
    "tool": "bandit",
    "findings": findings
}, indent=2))

print(f"[OK] Bandit normalized → {OUTPUT}")
