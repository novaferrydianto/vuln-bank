#!/usr/bin/env python3
import json
import os
import sys
from datetime import datetime
from typing import Any

GITHUB_EVENT_PATH = os.environ.get("GITHUB_EVENT_PATH", "")
LLM_REPORT = os.environ.get("LLM_REPORT", "security-reports/llm-findings.json")
GITHUB_OUTPUT_FILE = "llm_pr_comment_output.json"


def load_json(path: str) -> dict[str, Any]:
    if not os.path.exists(path):
        raise SystemExit(f"[ERROR] LLM report not found: {path}")

    # FIXED: remove unnecessary mode parameter
    with open(path) as f:
        return json.load(f)


def get_pr_number(event_path: str) -> int | None:
    if not event_path or not os.path.exists(event_path):
        return None

    # FIXED: remove unnecessary mode parameter
    with open(event_path) as f:
        data = json.load(f)

    return data.get("pull_request", {}).get("number")


def build_comment(findings: dict[str, Any]) -> str:
    issues = findings.get("issues", [])
    risk = findings.get("llm_risk_score", 0)

    lines = []
    lines.append("## 🤖 LLM Security Review Report")
    lines.append("")
    lines.append(f"**Risk Score:** {risk:.2f}")
    lines.append(f"**Generated At:** {datetime.utcnow().isoformat()}Z")
    lines.append("")

    if not issues:
        lines.append("### No issues detected by LLM model.")
        return "\n".join(lines)

    lines.append("### LLM-Identified Issues:")
    lines.append("")
    for i, issue in enumerate(issues, 1):
        severity = issue.get("severity", "UNKNOWN").upper()
        desc = issue.get("description", "No description")

        lines.append(f"**{i}. [{severity}]** {desc}")

    return "\n".join(lines)


def main():
    findings = load_json(LLM_REPORT)
    comment = build_comment(findings)

    payload = {"body": comment}

    # Output untuk GitHub Step Summary / PR comment action
    with open(GITHUB_OUTPUT_FILE, "w") as f:
        json.dump(payload, f, indent=2)

    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
