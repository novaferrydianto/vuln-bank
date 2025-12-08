#!/usr/bin/env python3
import json
from pathlib import Path
import sys

REPORT_DIR = Path("security-reports")

def main():
    src = REPORT_DIR / "asvs-scorecard.json"
    if not src.exists():
        print("ASVS scorecard not found")
        sys.exit(0)

    data = json.loads(src.read_text())

    print("## 🔐 ASVS Compliance Scorecard")
    print()
    print("| Section | Name | Pass % |")
    print("|---------|------|--------|")

    for key, value in data.items():
        name = value.get("name", key)
        pct = value.get("pass_pct", 0)
        print(f"| {key} | {name} | {pct}% |")

if __name__ == "__main__":
    main()
