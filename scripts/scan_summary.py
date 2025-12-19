#!/usr/bin/env python3
import json
import sys

out = {
    "new_findings": int(os.environ.get("NEW_FINDINGS", 0)),
    "solved": int(os.environ.get("SOLVED", 0))
}

with open("security-reports/scan-summary.json", "w") as f:
    json.dump(out, f, indent=2)
