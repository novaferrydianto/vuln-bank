#!/usr/bin/env python3

import os, json, sys
from datetime import datetime

def main():
    path = os.environ.get("LLM_SCAN_PATH", ".")
    out = os.environ.get("LLM_REPORT", "security-reports/llm-findings.json")

    # Simulated LLM score (replace with real API model)
    risk_score = 0.2
    issues = [
        {"msg": "Potential insecure string concat in SQL", "severity": "high"},
        {"msg": "JWT misconfiguration detected", "severity": "medium"},
    ]

    os.makedirs("security-reports", exist_ok=True)
    with open(out, "w") as f:
        json.dump({
            "path": path,
            "risk_score": risk_score,
            "issues": issues,
            "generated_at": datetime.utcnow().isoformat() + "Z"
        }, f, indent=2)

    print(json.dumps({"risk_score": risk_score}, indent=2))

if __name__ == "__main__":
    main()
