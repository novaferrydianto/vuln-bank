#!/usr/bin/env python3

import os, json

INFILE = "security-reports/llm-findings.json"
OUT = "security-reports/llm-comment.md"

def main():
    if not os.path.exists(INFILE):
        return

    data = json.load(open(INFILE))
    issues = data.get("issues", [])
    score = data.get("risk_score", 0)

    lines = []
    lines.append("## 🤖 LLM Security Review (Prettified)\n")
    lines.append(f"**AI Risk Score:** `{score}`\n")
    lines.append("\n### Findings:\n")

    for issue in issues:
        lines.append(f"- **{issue['severity'].upper()}** – {issue['msg']}")

    with open(OUT, "w") as f:
        f.write("\n".join(lines))

    print("LLM PR comment generated.")

if __name__ == "__main__":
    main()
