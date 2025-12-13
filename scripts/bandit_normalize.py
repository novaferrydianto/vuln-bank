#!/usr/bin/env python3
import json
import sys
from pathlib import Path

SEVERITY_MAP = {
    "LOW": "Low",
    "MEDIUM": "Medium",
    "HIGH": "High",
}

BANDIT_TO_OWASP_ASVS = {
    "B101": ("A09:2021-Security Logging and Monitoring Failures", "ASVS V10"),
    "B102": ("A03:2021-Injection", "ASVS V5"),
    "B103": ("A05:2021-Security Misconfiguration", "ASVS V14"),
    "B104": ("A05:2021-Security Misconfiguration", "ASVS V14"),
    "B105": ("A02:2021-Cryptographic Failures", "ASVS V2"),
    "B106": ("A02:2021-Cryptographic Failures", "ASVS V2"),
    "B107": ("A02:2021-Cryptographic Failures", "ASVS V2"),
    "B201": ("A05:2021-Security Misconfiguration", "ASVS V14"),
    "B301": ("A08:2021-Software and Data Integrity Failures", "ASVS V10"),
    "B302": ("A08:2021-Software and Data Integrity Failures", "ASVS V10"),
    "B303": ("A02:2021-Cryptographic Failures", "ASVS V2"),
    "B304": ("A02:2021-Cryptographic Failures", "ASVS V2"),
    "B305": ("A02:2021-Cryptographic Failures", "ASVS V2"),
    "B307": ("A03:2021-Injection", "ASVS V5"),
    "B401": ("A05:2021-Security Misconfiguration", "ASVS V14"),
    "B402": ("A05:2021-Security Misconfiguration", "ASVS V14"),
    "B404": ("A03:2021-Injection", "ASVS V5"),
    "B506": ("A08:2021-Software and Data Integrity Failures", "ASVS V10"),
}

def main(src, dst):
    src = Path(src)
    dst = Path(dst)

    if not src.exists():
        dst.write_text(json.dumps({"results": []}))
        return

    raw = json.loads(src.read_text())
    findings = []

    for item in raw.get("results", []):
        test_id = item.get("test_id", "B000")
        owasp, asvs = BANDIT_TO_OWASP_ASVS.get(
            test_id,
            ("A05:2021-Security Misconfiguration", "ASVS V14")
        )

        findings.append({
            "title": item.get("issue_text", "Bandit finding"),
            "severity": SEVERITY_MAP.get(item.get("issue_severity"), "Medium"),
            "confidence": "Medium",
            "file_path": item.get("filename"),
            "line": item.get("line_number"),
            "description": (
                f"{item.get('issue_text')}\n\n"
                f"Bandit Test ID: {test_id}\n"
                f"More Info: {item.get('more_info', '')}"
            ),
            "static_finding": True,
            "dynamic_finding": False,
            "references": f"{owasp}\n{asvs}",
            "tags": [
                "source:bandit",
                "type:sast",
                owasp,
                asvs
            ]
        })

    dst.write_text(json.dumps({"results": findings}, indent=2))
    print(f"[OK] Normalized Bandit findings: {len(findings)}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(0)
    main(sys.argv[1], sys.argv[2])
