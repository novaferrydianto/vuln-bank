#!/usr/bin/env python3
import json
from pathlib import Path

REPORT_DIR = Path("security-reports")
INPUT_JSON = REPORT_DIR / "asvs-scorecard.json"

def main():
    if not INPUT_JSON.exists():
        print("❌ asvs-scorecard.json not found")
        return

    data = json.loads(INPUT_JSON.read_text())

    print("## 🔐 ASVS Compliance Scorecard\n")
    print("| Section | Name | Pass % |")
    print("|--------|------|--------|")

    for key, value in data.items():
        # ✅ DEFENSIVE: skip invalid entries
        if not isinstance(value, dict):
            continue

        name = value.get("name", key)
        pct = value.get("pass_pct", 100.0)

        emoji = "✅" if pct == 100 else "❌" if pct < 80 else "⚠️"

        print(f"| {key} | {name} | {emoji} {pct}% |")

if __name__ == "__main__":
    main()
