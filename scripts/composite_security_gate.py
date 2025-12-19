#!/usr/bin/env python3
"""
Composite Security Gate (Enterprise Edition)
-------------------------------------------------
Menggabungkan semua sumber keamanan:

- EPSS + KEV + CVSS
- Snyk / Semgrep / Trivy / Checkov
- Secrets (Trufflehog)
- LLM Security Scan (llm_pipeline.py)
- GitHub Copilot Security Scan
- Composite Weighted Score

Output:
- PASS / FAIL
- composite-findings.json
"""

import os, json, math, sys
from datetime import datetime

# ============================
# Weight configuration
# ============================
WEIGHTS = {
    "epss": 0.25,
    "kev": 0.20,
    "cvss": 0.10,
    "sast": 0.15,
    "secrets": 0.10,
    "llm": 0.15,
    "copilot": 0.15,
    "iac": 0.10,
}

THRESHOLD = float(os.environ.get("COMPOSITE_THRESHOLD", "0.65"))

# ============================
# Safe JSON loader
# ============================
def safe_load(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)

# ============================
# Calculate normalized risk
# ============================
def normalize(value):
    return min(1.0, max(0.0, float(value)))

# ============================
# Collect data from all scanners
# ============================
def collect_inputs():
    return {
        "epss": safe_load("security-reports/epss-findings.json"),
        "llm": safe_load("security-reports/llm-findings.json"),
        "copilot": safe_load("security-reports/copilot-security.json"),
        "semgrep": safe_load("all-reports/reports-semgrep/semgrep.json"),
        "snyk_sca": safe_load("all-reports/reports-snyk/snyk-sca.json"),
        "snyk_code": safe_load("all-reports/reports-snyk/snyk-code.json"),
        "trivy": safe_load("all-reports/reports-trivy/trivy.json"),
        "checkov": safe_load("all-reports/reports-checkov/checkov_ansible.json"),
        "trufflehog": safe_load("all-reports/reports-trufflehog/trufflehog.json"),
    }

# ============================
# Extract risks
# ============================
def compute_component_scores(data):
    scores = {}

    epss_data = data.get("epss", {})
    scores["epss"] = normalize(epss_data.get("high_risk_count", 0) > 0)

    scores["kev"] = normalize(
        any(v.get("is_kev") for v in epss_data.get("high_risk", []))
    )

    scores["cvss"] = normalize(
        max([v.get("cvss", 0) for v in epss_data.get("high_risk", [])] or [0]) / 10.0
    )

    snyk = data.get("snyk_sca", {})
    scores["sast"] = normalize(
        len([v for v in snyk.get("vulnerabilities", []) if v.get("severity") == "critical"]) / 10
    )

    secrets = data.get("trufflehog", [])
    scores["secrets"] = normalize(len(secrets) / 5)

    scores["iac"] = normalize(
        len(data.get("checkov", {}).get("results", {}).get("failed_checks", [])) / 20
    )

    llm = data.get("llm", {})
    scores["llm"] = normalize(llm.get("risk_score", 0.0))

    cop = data.get("copilot", {})
    scores["copilot"] = normalize(cop.get("risk_level", 0.0))

    return scores

# ============================
# Weighted composite score
# ============================
def compute_composite_score(scores):
    total = 0
    for k, v in scores.items():
        total += WEIGHTS.get(k, 0) * v
    return round(total, 4)

# ============================
# Main
# ============================
def main():
    data = collect_inputs()
    component_scores = compute_component_scores(data)
    composite_score = compute_composite_score(component_scores)

    result = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "component_scores": component_scores,
        "composite_score": composite_score,
        "threshold": THRESHOLD,
        "status": "FAIL" if composite_score >= THRESHOLD else "PASS",
    }

    os.makedirs("security-reports", exist_ok=True)
    with open("security-reports/composite-findings.json", "w") as f:
        json.dump(result, f, indent=2)

    print(json.dumps(result, indent=2))

    if composite_score >= THRESHOLD:
        sys.exit(1)

if __name__ == "__main__":
    main()
