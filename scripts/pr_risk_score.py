#!/usr/bin/env python3
import json, sys

WEIGHTS = {"Critical":10,"High":7,"Medium":4,"Low":1,"ERROR":7}

def score(path):
    total = 0
    try:
        data = json.load(open(path))
    except:
        return 0

    for r in data.get("results", []):
        sev = (
            r.get("severity") or
            r.get("extra", {}).get("severity","").capitalize()
        )
        w = WEIGHTS.get(sev,0)

        tags = r.get("tags",[]) + r.get("extra",{}).get("metadata",{}).get("owasp",[])
        if any("A02" in t or "A03" in t for t in tags):
            w *= 1.5

        total += w
    return total

risk = score(sys.argv[1]) + score(sys.argv[2])
print(f"PR Risk Score: {int(risk)}")
open("security-reports/pr_risk_score.txt","w").write(str(int(risk)))
