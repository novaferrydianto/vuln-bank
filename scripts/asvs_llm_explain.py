#!/usr/bin/env python3
"""
Generate human-readable explanation for ASVS policy failure
"""

import json
import os
from openai import OpenAI

REPORT = "security-reports/normalized.json"
OUT = "security-reports/asvs-explanation.json"

SYSTEM_PROMPT = """
You are a senior application security architect.

Explain WHY deployment is blocked based on OWASP ASVS.

Rules:
- Explain in short paragraphs
- Reference ASVS sections
- Explain real-world impact
- No technical fluff
Return JSON with fields:
- summary
- violations (array)
- recommendation
"""

def main():
    data = json.load(open(REPORT))
    findings = data["findings"]
    summary = data["summary"]

    if not (summary["asvs_failed"] and summary["exploitable"]):
        print("No ASVS block → explanation skipped")
        return

    violations = [
        f for f in findings
        if f.get("asvs") and not f.get("baseline")
           and f["severity"] in ("HIGH", "CRITICAL")
    ]

    payload = {
        "summary": summary,
        "violations": violations
    }

    client = OpenAI(
        api_key=os.getenv("AI_API_KEY"),
        base_url=os.getenv("AI_API_ENDPOINT")
    )

    response = client.chat.completions.create(
        model="deepseek-r1",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(payload, indent=2)}
        ],
        temperature=0.2
    )

    explanation = json.loads(response.choices[0].message.content)

    with open(OUT, "w") as f:
        json.dump(explanation, f, indent=2)

    print("✅ ASVS explanation generated")

if __name__ == "__main__":
    main()
