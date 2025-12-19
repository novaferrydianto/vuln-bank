#!/usr/bin/env python3

import os, json
from datetime import datetime

FINDINGS = os.environ.get(
    "COMPOSITE_FINDINGS", "security-reports/composite-findings.json"
)
OUT = os.environ.get(
    "COMPOSITE_DASHBOARD", "security-reports/composite-dashboard.md"
)

def load_json(path):
    if not os.path.exists(path):
        raise SystemExit(f"Composite findings missing: {path}")
    with open(path) as f:
        return json.load(f)

def md_section(title):
    return f"## {title}\n\n"

def main():
    data = load_json(FINDINGS)
    comp = data["component_scores"]

    lines = []
    lines.append("# Composite Security Dashboard\n")
    lines.append(f"Generated: {data['generated_at']}\n\n")

    lines.append(md_section("Final Result"))
    lines.append(f"- Composite Score: **{data['composite_score']}**\n")
    lines.append(f"- Threshold: **{data['threshold']}**\n")
    lines.append(f"- Status: **{'🛑 FAIL' if data['status']=='FAIL' else '🟢 PASS'}**\n\n")

    lines.append(md_section("Component Scores"))
    for k, v in comp.items():
        lines.append(f"- **{k}** → `{v}`\n")

    os.makedirs("security-reports", exist_ok=True)
    with open(OUT, "w") as f:
        f.write("\n".join(lines))

    print("Composite dashboard generated.")

if __name__ == "__main__":
    main()
