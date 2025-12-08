#!/usr/bin/env python3
from dotenv import load_dotenv
import os
import argparse
import json

from agent import LLMSASTAgent
from utils import scan_codebase

# Load env
load_dotenv()

BASE_URL = os.getenv("AI_API_ENDPOINT", "https://api.llm7.io/v1")
API_KEY = os.getenv("AI_API_KEY")

BROKEN_ACCESS_CONTROL_SYSTEM = """
You are a senior application security engineer.

Detect BROKEN ACCESS CONTROL vulnerabilities.

Rules:
- Output STRICT JSON only
- Output MUST be an array
- No markdown
- No explanation outside JSON

Each finding:
- scanner: "llm-sast"
- category: "Access Control"
- severity: CRITICAL | HIGH | MEDIUM | LOW
- confidence: number (0.0 - 1.0)
- title
- description
- file
- line
- cwe
- asvs
- remediation
"""

def main():
    parser = argparse.ArgumentParser(description="LLM-SAST Scanner (Pipeline Ready)")
    parser.add_argument(
        "--scan-path",
        "-s",
        required=True,
        help="Path to source code",
    )
    args = parser.parse_args()

    project_root = os.path.abspath(args.scan_path)
    code_context = scan_codebase(project_root)

    agent = LLMSASTAgent(
        model="deepseek-r1",
        system_prompt=BROKEN_ACCESS_CONTROL_SYSTEM,
        base_url=BASE_URL,
        api_key=API_KEY,
    )

    findings = agent.analyze(code_context)

    # ✅ Enforce array
    if not isinstance(findings, list):
        raise ValueError("LLM-SAST output is not an array")

    # ✅ Write pipeline artifact
    out_path = os.path.join("security-reports", "llm-sast.json")
    os.makedirs("security-reports", exist_ok=True)

    with open(out_path, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"✅ LLM-SAST completed, findings: {len(findings)}")
    print(f"📄 Report written to {out_path}")

if __name__ == "__main__":
    main()
