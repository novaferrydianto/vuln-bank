#!/usr/bin/env python3
import json
from pathlib import Path

ZAP_JSON = Path("security-reports/zap/zap.json")

SEV_MAP = {
    "High": "CRITICAL",
    "Medium": "HIGH",
    "Low": "MEDIUM",
    "Informational": "LOW"
}

def main():
    if not ZAP_JSON.exists():
        print("[]")
        return

    data = json.loads(ZAP_JSON.read_text())

    findings = []

    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            title = alert.get("alert")
            risk = alert.get("risk")
            description = alert.get("description", "")
            solution = alert.get("solution", "")
            refs = alert.get("reference", "")
            instances = alert.get("instances", [])

            severity = SEV_MAP.get(risk, "LOW")

            findings.append({
                "title": title,
                "severity": severity,
                "risk": risk,
                "description": description,
                "solution": solution,
                "reference": refs,
                "instances": [i.get("uri") for i in instances if i.get("uri")]
            })

    print(json.dumps(findings))
    
if __name__ == "__main__":
    main()
