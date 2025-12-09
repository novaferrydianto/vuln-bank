#!/usr/bin/env python3
import json
from pathlib import Path

REPORT_DIR = Path("security-reports")
SCORECARD_JSON = REPORT_DIR / "asvs-scorecard.json"
NORMALIZED_JSON = REPORT_DIR / "normalized.json"


def main():
    scorecard = json.loads(SCORECARD_JSON.read_text())
    normalized = json.loads(NORMALIZED_JSON.read_text())

    summary = normalized.get("summary", {})
    gate_blocked = summary.get("asvs_failed") and summary.get("exploitable")

    print("## 🔐 ASVS Compliance Scorecard\n")
    print("| Section | Name | Status | Pass % |")
    print("|--------|------|--------|--------|")

    for section, data in scorecard.items():
        if not isinstance(data, dict):
            continue

        name = data.get("name", section)
        pct = data.get("pass_pct", 100)

        # ✅ Color logic
        if pct == 100:
            status = "🟢 PASS"
        elif gate_blocked:
            status = "🔴 FAIL (BLOCKING)"
        else:
            status = "🟡 WARNING"

        print(f"| {section} | {name} | {status} | {pct}% |")

    # ✅ Overall Verdict Banner
    print("\n---\n")
    if gate_blocked:
        print("### 🚫 Security Gate Result: **BLOCKED**")
        print("> Exploitable ASVS violations detected. Deployment denied.")
    else:
        print("### ✅ Security Gate Result: **PASS**")
        print("> No exploitable ASVS violations found.")


if __name__ == "__main__":
    main()
