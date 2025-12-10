#!/usr/bin/env python3
"""
Merge Bandit + Semgrep JSON → SonarQube Generic Issue Format
"""

import json
from pathlib import Path

REPORT_DIR = Path("security-reports")

BANDIT_JSON = REPORT_DIR / "bandit.json"
SEMGREP_JSON = REPORT_DIR / "semgrep.json"

# Must match sonar-project.properties
OUT_JSON = REPORT_DIR / "sonar-external.json"


def load_json(path: Path):
    if not path.is_file():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def bandit_to_sonar(data):
    issues = []
    for r in data.get("results", []):
        severity_raw = (r.get("issue_severity") or "").upper()
        if severity_raw == "HIGH":
            sev = "CRITICAL"
        elif severity_raw == "MEDIUM":
            sev = "MAJOR"
        else:
            sev = "MINOR"

        issues.append({
            "engineId": "bandit",
            "ruleId": r.get("test_id") or "bandit-unknown",
            "severity": sev,
            "type": "VULNERABILITY",
            "primaryLocation": {
                "message": r.get("issue_text") or "Bandit finding",
                "filePath": r.get("filename"),
                "textRange": {
                    "startLine": r.get("line_number", 1),
                    "endLine": r.get("line_number", 1),
                },
            },
        })
    return issues


def semgrep_to_sonar(data):
    issues = []
    for r in data.get("results", []):
        extra = r.get("extra") or {}
        sev_raw = (extra.get("severity") or "").upper()

        if sev_raw in ("CRITICAL", "ERROR", "HIGH"):
            sev = "CRITICAL"
        elif sev_raw == "MEDIUM":
            sev = "MAJOR"
        else:
            sev = "MINOR"

        start = r.get("start") or {}
        end = r.get("end") or {}

        issues.append({
            "engineId": "semgrep",
            "ruleId": r.get("check_id") or "semgrep-unknown",
            "severity": sev,
            "type": "VULNERABILITY",
            "primaryLocation": {
                "message": extra.get("message")
                           or r.get("check_id")
                           or "Semgrep finding",
                "filePath": r.get("path"),
                "textRange": {
                    "startLine": start.get("line", 1),
                    "endLine": end.get("line", start.get("line", 1)),
                },
            },
        })
    return issues


def main():
    bandit_data = load_json(BANDIT_JSON)
    semgrep_data = load_json(SEMGREP_JSON)

    issues = []
    issues.extend(bandit_to_sonar(bandit_data))
    issues.extend(semgrep_to_sonar(semgrep_data))

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    with OUT_JSON.open("w", encoding="utf-8") as f:
        json.dump({"issues": issues}, f, indent=2)

    print(
        f"[INFO] Sonar external issues generated: {OUT_JSON} "
        f"(total issues = {len(issues)})"
    )


if __name__ == "__main__":
    main()
