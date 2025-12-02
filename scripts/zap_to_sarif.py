import json, sys

with open(sys.argv[1]) as f:
    zap = json.load(f)

sarif = {
    "version": "2.1.0",
    "runs": [{
        "tool": {
            "driver": {
                "name": "OWASP ZAP",
                "informationUri": "https://www.zaproxy.org/",
                "rules": []
            }
        },
        "results": []
    }]
}

for site in zap.get("site", []):
    for alert in site.get("alerts", []):
        level = "error" if alert.get("riskcode") == "3" else "warning"

        sarif["runs"][0]["results"].append({
            "level": level,
            "message": {"text": alert.get("alert")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": alert.get("uri")}
                }
            }]
        })

with open(sys.argv[2], "w") as f:
    json.dump(sarif, f, indent=2)
