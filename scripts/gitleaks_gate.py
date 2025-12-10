import json, sys

SARIF = sys.argv[1]
FAIL_LEVELS = {"CRITICAL", "HIGH"}

data = json.load(open(SARIF))
results = data["runs"][0]["results"]

violations = [r for r in results if r["properties"].get("severity") in FAIL_LEVELS]

if violations:
    print("🚨 Secret gate FAILED")
    for v in violations:
        print(f"- {v['ruleId']} ({v['properties']['severity']})")
    sys.exit(1)

print("✅ Secret gate PASSED")
