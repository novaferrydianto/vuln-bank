#!/usr/bin/env python3
"""
Convert Bandit JSON → SonarQube Generic Issue Format
"""

import json
from pathlib import Path

INPUT = Path("security-reports/bandit.json")
OUTPUT = Path("security-reports/sonar-bandit.json")

# Mapping Bandit → SonarQube severity
SONAR_SEV = {
    "HIGH": "CRITICAL",
    "MEDIUM": "MAJOR",
    "LOW": "MINOR",
}

def main():
    if not INPUT.exists():
        raise FileNotFoundError(f"Bandit output missing: {INPUT}")

    with INPUT.open() as f:
        bandit = json.load(f)

    issues = []

    for r in bandit.get("results", []):
        bandit_sev = r.get("issue_severity", "LOW").upper()
        sonar_sev = SONAR_SEV.get(bandit_sev, "INFO")

        issue = {
            "engineId": "bandit",
            "ruleId": r.get("test_id"),
            "type": "VULNERABILITY",
            "severity": sonar_sev,

            # Required by SonarQube Generic Issue Format
            "primaryLocation": {
                "message": r.get("issue_text"),
                "filePath": r.get("filename"),
                "textRange": {
                    "startLine": r.get("line_number"),
                    "endLine": r.get("line_number"),
                },
            },

            # Optional but recommended → Sonar uses this in UI
            "effortMinutes": 5 if sonar_sev in ("CRITICAL", "MAJOR") else 2,
        }

        issues.append(issue)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w") as f:
        json.dump({"issues": issues}, f, indent=2)

    print(f"[OK] Converted {len(issues)} Bandit issues → {OUTPUT}")


if __name__ == "__main__":
    main()
