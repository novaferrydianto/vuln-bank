#!/usr/bin/env python3
"""
security_scorecard.py
-------------------------------------------------------
Build an executive-friendly security scorecard for:
- OWASP Coverage
- EPSS Risk Index
- CVSS Severity Index
- SAST (Semgrep)
- SCA (Snyk)
- IaC (Checkov)
- DAST (ZAP optional)

Outputs:
security-reports/security-scorecard.json
"""

import os
import json
from datetime import datetime


def safe_read(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def score_from_epss(epss):
    if not epss:
        return {"high_risk": 0, "risk_score": 0}

    hr = epss.get("high_risk", [])
    risk_score = sum(min(1.0, item.get("epss", 0)) for item in hr)
    return {
        "high_risk": len(hr),
        "risk_score": round(risk_score, 3)
    }


def score_from_snyk(data):
    if not data:
        return {"critical": 0, "high": 0, "medium": 0}
    vulns = data.get("vulnerabilities", [])
    return {
        "critical": sum(1 for x in vulns if x.get("severity") == "critical"),
        "high": sum(1 for x in vulns if x.get("severity") == "high"),
        "medium": sum(1 for x in vulns if x.get("severity") == "medium"),
    }


def main():
    epss = safe_read("security-reports/epss-findings.json")
    snyk_sca = safe_read("all-reports/reports-snyk/snyk-sca.json")
    semgrep = safe_read("all-reports/reports-semgrep/semgrep.json")
    checkov = safe_read("all-reports/reports-checkov/checkov_ansible.json")

    scorecard = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "epss": score_from_epss(epss),
        "snyk": score_from_snyk(snyk_sca),
        "semgrep_findings": semgrep.get("results", []) if semgrep else [],
        "checkov_failed": len(checkov.get("results", {}).get("failed_checks", [])) if checkov else 0,
    }

    os.makedirs("security-reports", exist_ok=True)
    with open("security-reports/security-scorecard.json", "w") as f:
        json.dump(scorecard, f, indent=2)

    print(json.dumps(scorecard, indent=2))


if __name__ == "__main__":
    main()
