import json

with open("security-reports/bandit.json") as f:
    data = json.load(f)

issues = []
for r in data.get("results", []):
    issues.append({
        "engineId": "bandit",
        "ruleId": r.get("test_id"),
        "severity": "CRITICAL" if r.get("issue_severity") == "HIGH" else "MAJOR",
        "type": "VULNERABILITY",
        "primaryLocation": {
            "message": r.get("issue_text"),
            "filePath": r.get("filename"),
            "textRange": {
                "startLine": r.get("line_number"),
                "endLine": r.get("line_number")
            }
        }
    })

with open("security-reports/sonar-bandit.json", "w") as f:
    json.dump({"issues": issues}, f, indent=2)
