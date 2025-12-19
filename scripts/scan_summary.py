#!/usr/bin/env python3
import os
import json

def main():
    # Values injected from GitHub Actions environment
    new_findings = int(os.environ.get("NEW_FINDINGS", "0"))
    solved = int(os.environ.get("SOLVED", "0"))

    summary = {
        "new_findings": new_findings,
        "solved": solved
    }

    os.makedirs("security-reports", exist_ok=True)

    with open("security-reports/scan-summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print(f"[SUMMARY] new={new_findings}, solved={solved}")

if __name__ == "__main__":
    main()
